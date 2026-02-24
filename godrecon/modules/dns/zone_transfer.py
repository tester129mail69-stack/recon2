"""Zone transfer checker for GODRECON.

Attempts AXFR zone transfers against every nameserver of a target domain.
A successful zone transfer is a **critical** security finding.
"""

from __future__ import annotations

import asyncio
import socket
from typing import Any, Dict, List, Optional

from godrecon.utils.dns_resolver import AsyncDNSResolver
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)


class ZoneTransferChecker:
    """Check whether DNS nameservers allow AXFR zone transfers.

    Uses raw TCP socket connections to port 53 to attempt zone transfers,
    which avoids additional dependencies on ``dnspython``.

    Example::

        async with AsyncDNSResolver() as resolver:
            checker = ZoneTransferChecker(resolver)
            result = await checker.check("example.com")
    """

    def __init__(self, resolver: AsyncDNSResolver, timeout: int = 5) -> None:
        """Initialise the checker.

        Args:
            resolver: Configured DNS resolver instance.
            timeout: TCP connection timeout in seconds.
        """
        self._resolver = resolver
        self._timeout = timeout

    async def check(self, domain: str) -> Dict[str, Any]:
        """Attempt zone transfers against all nameservers for *domain*.

        Returns a dict with:

        * ``nameservers`` — list of NS hostnames
        * ``vulnerable`` — bool, True if any NS allowed the transfer
        * ``vulnerable_ns`` — list of nameservers that allowed transfer
        * ``zone_records`` — dict mapping NS to list of records received

        Args:
            domain: Target domain.

        Returns:
            Dict with zone transfer results.
        """
        ns_records = await self._safe_resolve(domain, "NS")
        nameservers = [ns.rstrip(".") for ns in ns_records]

        vulnerable_ns: List[str] = []
        zone_records: Dict[str, List[str]] = {}

        tasks = [
            asyncio.create_task(self._attempt_axfr(domain, ns))
            for ns in nameservers
        ]
        gathered = await asyncio.gather(*tasks, return_exceptions=True)

        for ns, result in zip(nameservers, gathered):
            if isinstance(result, Exception):
                logger.debug("AXFR attempt for %s via %s raised: %s", domain, ns, result)
                continue
            records = result  # type: ignore[assignment]
            if records:
                vulnerable_ns.append(ns)
                zone_records[ns] = records
                logger.warning(
                    "Zone transfer ALLOWED on %s for %s — %d records",
                    ns,
                    domain,
                    len(records),
                )

        return {
            "nameservers": nameservers,
            "vulnerable": bool(vulnerable_ns),
            "vulnerable_ns": vulnerable_ns,
            "zone_records": zone_records,
        }

    async def _attempt_axfr(self, domain: str, nameserver: str) -> List[str]:
        """Try an AXFR zone transfer against *nameserver* for *domain*.

        Uses a minimal DNS over TCP wire-format AXFR request.

        Args:
            domain: Domain to transfer.
            nameserver: Nameserver hostname or IP.

        Returns:
            List of raw record strings extracted from the response, or empty
            list if the transfer was refused or failed.
        """
        loop = asyncio.get_event_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, self._axfr_sync, domain, nameserver),
                timeout=float(self._timeout),
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("AXFR %s via %s: %s", domain, nameserver, exc)
            return []

    def _axfr_sync(self, domain: str, nameserver: str) -> List[str]:
        """Synchronous AXFR attempt (runs in a thread-pool executor).

        Sends a raw AXFR request over TCP and parses the response to extract
        any readable resource records.

        Args:
            domain: Domain name to request.
            nameserver: Nameserver to query.

        Returns:
            List of record strings, or empty list.
        """
        records: List[str] = []
        try:
            axfr_query = self._build_axfr_query(domain)
            ns_ip = socket.gethostbyname(nameserver)
            with socket.create_connection((ns_ip, 53), timeout=self._timeout) as sock:
                # DNS over TCP uses a 2-byte length prefix
                length_prefix = len(axfr_query).to_bytes(2, "big")
                sock.sendall(length_prefix + axfr_query)

                data = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    # DNS messages are capped at 65535 bytes (16-bit TCP length field)
                    if len(data) > 65535:
                        break

            if len(data) > 12:
                # Check RCODE in the DNS header (bits 0-3 of byte 3)
                rcode = data[3] & 0x0F
                if rcode == 0:
                    # NOERROR — try to parse minimal record text
                    records = self._parse_axfr_response(data, domain)
        except Exception as exc:  # noqa: BLE001
            logger.debug("AXFR sync %s via %s: %s", domain, nameserver, exc)
        return records

    @staticmethod
    def _build_axfr_query(domain: str) -> bytes:
        """Build a minimal DNS AXFR query packet.

        Args:
            domain: Domain name.

        Returns:
            Raw DNS query bytes (without TCP length prefix).
        """
        # Transaction ID = 0x0001, Standard query, QR=0, Opcode=0, RD=1
        header = bytes([
            0x00, 0x01,  # ID
            0x00, 0x00,  # Flags: standard query
            0x00, 0x01,  # QDCOUNT = 1
            0x00, 0x00,  # ANCOUNT = 0
            0x00, 0x00,  # NSCOUNT = 0
            0x00, 0x00,  # ARCOUNT = 0
        ])
        # Encode QNAME
        qname = b""
        for label in domain.split("."):
            encoded = label.encode("ascii")
            qname += bytes([len(encoded)]) + encoded
        qname += b"\x00"
        # QTYPE = AXFR (252), QCLASS = IN (1)
        question = qname + bytes([0x00, 0xFC, 0x00, 0x01])
        return header + question

    @staticmethod
    def _parse_axfr_response(data: bytes, domain: str) -> List[str]:
        """Extract a summary list of records from a raw AXFR TCP response.

        This is intentionally lenient — it just looks for recognisable ASCII
        strings in the payload and returns a best-effort record list.

        Args:
            data: Raw TCP DNS response bytes (may include length prefix).
            domain: Original domain queried.

        Returns:
            List of record summary strings.
        """
        # Strip the 2-byte TCP length prefix if present
        if len(data) > 2:
            msg_len = int.from_bytes(data[:2], "big")
            if msg_len + 2 <= len(data):
                data = data[2:]

        # Minimal heuristic: count answer RRs from the DNS header
        if len(data) < 12:
            return []

        an_count = int.from_bytes(data[6:8], "big")
        if an_count == 0:
            return []

        # Return a generic notice rather than trying to fully parse all RR types
        return [f"AXFR zone transfer successful — approximately {an_count} records received from {domain}"]

    async def _safe_resolve(self, domain: str, record_type: str) -> List[str]:
        """Resolve *record_type* for *domain*, returning ``[]`` on error.

        Args:
            domain: Domain name.
            record_type: DNS record type.

        Returns:
            List of record strings.
        """
        try:
            return await self._resolver.resolve(domain, record_type)
        except Exception as exc:  # noqa: BLE001
            logger.debug("ZT resolve %s %s: %s", record_type, domain, exc)
            return []
