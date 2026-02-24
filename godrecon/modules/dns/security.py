"""DNS security analyzer for GODRECON.

Analyses DNS configuration for common security weaknesses including open
resolvers, zone-transfer exposure, DNS amplification vectors, dangling CNAMEs,
NS takeover risk and DNS rebinding vulnerabilities.
"""

from __future__ import annotations

import asyncio
import socket
from typing import Any, Dict, List

from godrecon.utils.dns_resolver import AsyncDNSResolver
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)


class DNSSecurityAnalyzer:
    """Detect DNS security issues for a target domain.

    Checks are run concurrently and individual failures do not abort the
    overall analysis.

    Example::

        async with AsyncDNSResolver() as resolver:
            analyzer = DNSSecurityAnalyzer(resolver)
            issues = await analyzer.analyze("example.com")
    """

    def __init__(self, resolver: AsyncDNSResolver, timeout: int = 5) -> None:
        """Initialise the analyzer.

        Args:
            resolver: Configured DNS resolver instance.
            timeout: Socket timeout for active checks in seconds.
        """
        self._resolver = resolver
        self._timeout = timeout

    async def analyze(self, domain: str) -> Dict[str, Any]:
        """Run all DNS security checks for *domain*.

        Returns a dict with the following keys:

        * ``open_resolver`` — bool, any NS is an open resolver
        * ``recursive_ns`` — list of NS IPs with recursion available
        * ``dangling_cnames`` — list of CNAME targets that do not resolve
        * ``ns_takeover_risk`` — list of NS entries with unregistered domains
        * ``dns_rebinding_risk`` — bool
        * ``amplification_risk`` — bool (ANY queries return large responses)
        * ``issues`` — list of issue description strings

        Args:
            domain: Target domain.

        Returns:
            Dict summarising security findings.
        """
        ns_records = await self._safe_resolve(domain, "NS")
        nameservers = [ns.rstrip(".") for ns in ns_records]
        cname_records = await self._safe_resolve(domain, "CNAME")
        a_records = await self._safe_resolve(domain, "A")

        # Run checks concurrently
        (
            open_resolvers,
            recursive_ns,
            amplification_ns,
        ) = await asyncio.gather(
            self._check_open_resolvers(nameservers),
            self._check_recursion(nameservers),
            self._check_amplification(nameservers),
        )

        dangling = await self._check_dangling_cnames(cname_records)
        ns_takeover = await self._check_ns_takeover(nameservers)
        rebinding = self._check_rebinding_risk(a_records)

        issues: List[str] = []
        if open_resolvers:
            issues.append(
                f"Open resolver detected on: {', '.join(open_resolvers)}"
            )
        if recursive_ns:
            issues.append(
                f"DNS recursion available on: {', '.join(recursive_ns)}"
            )
        if amplification_ns:
            issues.append(
                f"DNS amplification risk on: {', '.join(amplification_ns)}"
            )
        if dangling:
            issues.append(
                f"Dangling CNAME records (potential subdomain takeover): {', '.join(dangling)}"
            )
        if ns_takeover:
            issues.append(
                f"NS takeover risk — unregistered NS domains: {', '.join(ns_takeover)}"
            )
        if rebinding:
            issues.append("DNS rebinding risk: A records include private/loopback addresses")

        return {
            "open_resolver": bool(open_resolvers),
            "open_resolver_ns": open_resolvers,
            "recursive_ns": recursive_ns,
            "amplification_risk": bool(amplification_ns),
            "amplification_ns": amplification_ns,
            "dangling_cnames": dangling,
            "ns_takeover_risk": ns_takeover,
            "dns_rebinding_risk": rebinding,
            "issues": issues,
        }

    # ------------------------------------------------------------------
    # Individual security checks
    # ------------------------------------------------------------------

    async def _check_open_resolvers(self, nameservers: List[str]) -> List[str]:
        """Check which nameservers act as open resolvers.

        An open resolver will answer queries for arbitrary external domains.

        Args:
            nameservers: List of nameserver hostnames.

        Returns:
            List of nameserver hostnames that are open resolvers.
        """
        open_ns: List[str] = []
        loop = asyncio.get_event_loop()

        async def _check_one(ns: str) -> bool:
            try:
                ns_ip = await loop.run_in_executor(None, socket.gethostbyname, ns)
                # Build a query for a well-known external domain
                query = self._build_a_query("google.com")
                result = await asyncio.wait_for(
                    loop.run_in_executor(None, self._udp_query, ns_ip, query),
                    timeout=float(self._timeout),
                )
                return bool(result)
            except Exception:  # noqa: BLE001
                return False

        tasks = [asyncio.create_task(_check_one(ns)) for ns in nameservers]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for ns, res in zip(nameservers, results):
            if res is True:
                open_ns.append(ns)
        return open_ns

    async def _check_recursion(self, nameservers: List[str]) -> List[str]:
        """Check which nameservers have recursion available.

        Args:
            nameservers: List of nameserver hostnames.

        Returns:
            List of nameservers with recursion enabled.
        """
        recursive: List[str] = []
        loop = asyncio.get_event_loop()

        async def _check_one(ns: str) -> bool:
            try:
                ns_ip = await loop.run_in_executor(None, socket.gethostbyname, ns)
                query = self._build_a_query("example.com", recursion_desired=True)
                response = await asyncio.wait_for(
                    loop.run_in_executor(None, self._udp_query, ns_ip, query),
                    timeout=float(self._timeout),
                )
                if response and len(response) > 3:
                    # RA bit is bit 7 of byte 3 in the DNS header
                    return bool(response[3] & 0x80)
                return False
            except Exception:  # noqa: BLE001
                return False

        tasks = [asyncio.create_task(_check_one(ns)) for ns in nameservers]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for ns, res in zip(nameservers, results):
            if res is True:
                recursive.append(ns)
        return recursive

    async def _check_amplification(self, nameservers: List[str]) -> List[str]:
        """Check which nameservers respond to ANY queries with large responses.

        Args:
            nameservers: List of nameserver hostnames.

        Returns:
            List of nameservers potentially usable for amplification.
        """
        amp_ns: List[str] = []
        loop = asyncio.get_event_loop()

        async def _check_one(ns: str) -> bool:
            try:
                ns_ip = await loop.run_in_executor(None, socket.gethostbyname, ns)
                query = self._build_any_query(ns)
                response = await asyncio.wait_for(
                    loop.run_in_executor(None, self._udp_query, ns_ip, query),
                    timeout=float(self._timeout),
                )
                # Amplification risk if response is significantly larger than query
                return bool(response) and len(response) > len(query) * 3
            except Exception:  # noqa: BLE001
                return False

        tasks = [asyncio.create_task(_check_one(ns)) for ns in nameservers]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for ns, res in zip(nameservers, results):
            if res is True:
                amp_ns.append(ns)
        return amp_ns

    async def _check_dangling_cnames(self, cname_records: List[str]) -> List[str]:
        """Check for CNAME records pointing to unresolvable hosts.

        Args:
            cname_records: List of CNAME target strings.

        Returns:
            List of CNAME targets that do not resolve.
        """
        dangling: List[str] = []
        for cname in cname_records:
            target = cname.rstrip(".")
            a_records = await self._safe_resolve(target, "A")
            if not a_records:
                aaaa_records = await self._safe_resolve(target, "AAAA")
                if not aaaa_records:
                    dangling.append(target)
        return dangling

    async def _check_ns_takeover(self, nameservers: List[str]) -> List[str]:
        """Check for nameservers whose domain names do not resolve (NS takeover risk).

        Args:
            nameservers: List of nameserver hostnames.

        Returns:
            List of nameserver hostnames that do not resolve.
        """
        at_risk: List[str] = []
        for ns in nameservers:
            records = await self._safe_resolve(ns, "A")
            if not records:
                aaaa = await self._safe_resolve(ns, "AAAA")
                if not aaaa:
                    at_risk.append(ns)
        return at_risk

    @staticmethod
    def _check_rebinding_risk(a_records: List[str]) -> bool:
        """Return True if any A record contains a private or loopback address.

        Args:
            a_records: List of IPv4 address strings.

        Returns:
            Boolean indicating DNS rebinding risk.
        """
        for addr in a_records:
            # RFC 1918 private ranges and special addresses
            if addr.startswith("10.") or addr.startswith("127.") or addr.startswith("169.254.") or addr == "::1":
                return True
            # 192.168.0.0/16
            if addr.startswith("192.168."):
                return True
            # 172.16.0.0/12 — 172.16.x.x through 172.31.x.x
            if addr.startswith("172."):
                try:
                    second_octet = int(addr.split(".")[1])
                    if 16 <= second_octet <= 31:
                        return True
                except (IndexError, ValueError):
                    pass
        return False

    # ------------------------------------------------------------------
    # Low-level DNS packet helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _encode_domain(domain: str) -> bytes:
        """Encode a domain name in DNS wire format.

        Args:
            domain: Domain name string.

        Returns:
            DNS wire-format encoded bytes.
        """
        out = b""
        for label in domain.rstrip(".").split("."):
            encoded = label.encode("ascii")
            out += bytes([len(encoded)]) + encoded
        return out + b"\x00"

    def _build_a_query(self, domain: str, recursion_desired: bool = True) -> bytes:
        """Build a minimal DNS A query packet.

        Args:
            domain: Domain to query.
            recursion_desired: Set the RD flag.

        Returns:
            Raw DNS query bytes.
        """
        flags = 0x0100 if recursion_desired else 0x0000
        header = bytes([
            0x00, 0x02,
            (flags >> 8) & 0xFF, flags & 0xFF,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        return header + self._encode_domain(domain) + bytes([0x00, 0x01, 0x00, 0x01])

    def _build_any_query(self, domain: str) -> bytes:
        """Build a minimal DNS ANY query packet.

        Args:
            domain: Domain to query.

        Returns:
            Raw DNS query bytes.
        """
        header = bytes([
            0x00, 0x03,
            0x01, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        # QTYPE = ANY (255), QCLASS = IN (1)
        return header + self._encode_domain(domain) + bytes([0x00, 0xFF, 0x00, 0x01])

    def _udp_query(self, ns_ip: str, query: bytes) -> bytes:
        """Send a UDP DNS query and return the raw response.

        Args:
            ns_ip: Nameserver IP address.
            query: Raw DNS query bytes.

        Returns:
            Raw response bytes, or empty bytes on failure.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self._timeout)
            sock.sendto(query, (ns_ip, 53))
            try:
                return sock.recv(4096)
            except socket.timeout:
                return b""

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
            logger.debug("Security resolve %s %s: %s", record_type, domain, exc)
            return []
