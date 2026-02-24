"""Zone transfer (AXFR) subdomain source."""

from __future__ import annotations

from typing import Set

from godrecon.utils.dns_resolver import AsyncDNSResolver
from godrecon.modules.subdomains.sources.base import SubdomainSource


class ZoneTransferSource(SubdomainSource):
    """Attempt DNS zone transfers (AXFR) against all authoritative name servers.

    Zone transfers are a fundamental DNS feature that, when misconfigured, can
    expose the full zone contents.  No API key required — purely DNS-based.
    """

    name = "zone_transfer"
    description = "DNS AXFR zone transfer attempt"
    requires_api_key = False

    async def fetch(self, domain: str) -> Set[str]:
        """Attempt AXFR zone transfers for *domain*.

        Args:
            domain: Root domain to attempt zone transfer on.

        Returns:
            Set of discovered subdomain strings.
        """
        results: Set[str] = set()
        try:
            import asyncio
            import socket

            async with AsyncDNSResolver() as resolver:
                # Get NS records for the domain
                ns_records = await resolver.resolve(domain, "NS")
                if not ns_records:
                    return results

                for ns in ns_records:
                    # Extract hostname from NS record (may be "priority host" format)
                    ns_host = ns.split()[-1].rstrip(".")
                    try:
                        await asyncio.wait_for(
                            self._axfr(ns_host, domain, results),
                            timeout=10.0,
                        )
                    except asyncio.TimeoutError:
                        self.logger.debug("AXFR timed out for %s via %s", domain, ns_host)
                    except Exception as exc:  # noqa: BLE001
                        self.logger.debug("AXFR failed for %s via %s: %s", domain, ns_host, exc)
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("Zone transfer error: %s", exc)
        return results

    async def _axfr(self, nameserver: str, domain: str, results: Set[str]) -> None:
        """Perform a single AXFR attempt against *nameserver*.

        Args:
            nameserver: Nameserver hostname to query.
            domain: Domain to request zone transfer for.
            results: Mutable set to add discovered subdomains into.
        """
        import asyncio
        import socket

        # Resolve the nameserver's IP
        loop = asyncio.get_event_loop()
        try:
            infos = await loop.getaddrinfo(nameserver, 53, type=socket.SOCK_STREAM)
        except Exception:  # noqa: BLE001
            return
        if not infos:
            return
        ns_ip = infos[0][4][0]

        # Build a raw AXFR query
        # Message: ID=0xABCD, flags=0x0000 (query), QDCOUNT=1
        import struct

        qname = b""
        for label in domain.split("."):
            encoded = label.encode("ascii")
            qname += bytes([len(encoded)]) + encoded
        qname += b"\x00"

        query = struct.pack(">HHHHHH", 0xABCD, 0x0000, 1, 0, 0, 0)
        query += qname
        query += struct.pack(">HH", 252, 1)  # QTYPE=AXFR, QCLASS=IN

        # Prepend 2-byte length for TCP
        tcp_msg = struct.pack(">H", len(query)) + query

        try:
            reader, writer = await asyncio.open_connection(ns_ip, 53)
            writer.write(tcp_msg)
            await writer.drain()

            suffix = f".{domain}".encode()
            domain_bytes = domain.encode()

            # Read responses until connection closes
            while True:
                length_data = await asyncio.wait_for(reader.read(2), timeout=5.0)
                if len(length_data) < 2:
                    break
                msg_len = struct.unpack(">H", length_data)[0]
                msg = await asyncio.wait_for(reader.read(msg_len), timeout=5.0)
                if not msg:
                    break
                # Crude extraction: find labels in the response
                self._extract_names_from_wire(msg, domain, results)

            writer.close()
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass

    @staticmethod
    def _extract_names_from_wire(data: bytes, domain: str, results: Set[str]) -> None:
        """Attempt to extract domain names from a raw DNS wire-format message.

        This is a best-effort heuristic parser rather than a full DNS parser.

        Args:
            data: Raw DNS message bytes.
            domain: Root domain to filter results.
            results: Mutable set to add discovered subdomains into.
        """
        import re
        # Try to decode readable ASCII-looking hostnames
        text = data.decode("latin-1")
        pattern = re.compile(r'([\w\-]+(?:\.[\w\-]+)+)', re.ASCII)
        suffix = f".{domain}"
        for match in pattern.finditer(text):
            candidate = match.group(1).lower()
            if candidate.endswith(suffix) or candidate == domain:
                results.add(candidate)
