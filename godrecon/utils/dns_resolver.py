"""Async DNS resolver for GODRECON.

Provides :class:`AsyncDNSResolver` — an aiodns-based resolver with caching,
support for all record types, DNS-over-HTTPS, wildcard detection, and bulk
concurrent resolution.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import aiodns
    _AIODNS_AVAILABLE = True
except ImportError:
    _AIODNS_AVAILABLE = False

try:
    import aiohttp as _aiohttp
    _AIOHTTP_AVAILABLE = True
except ImportError:
    _AIOHTTP_AVAILABLE = False

from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# Record types supported for direct aiodns queries
_AIODNS_RECORD_TYPES: Set[str] = {
    "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "PTR", "CAA",
}


def _cache_key(domain: str, record_type: str) -> str:
    """Return an MD5 cache key for a DNS query."""
    return hashlib.md5(f"{domain}:{record_type}".encode()).hexdigest()


class DNSCacheEntry:
    """A cached DNS record with TTL tracking."""

    def __init__(self, records: List[Any], ttl: int = 300) -> None:
        self.records = records
        self.expires_at = time.monotonic() + ttl

    @property
    def expired(self) -> bool:
        return time.monotonic() > self.expires_at


class AsyncDNSResolver:
    """Async DNS resolver with caching, retries, and bulk support.

    Example::

        async with AsyncDNSResolver(nameservers=["8.8.8.8", "1.1.1.1"]) as dns:
            records = await dns.resolve("example.com", "A")
            print(records)
    """

    def __init__(
        self,
        nameservers: Optional[List[str]] = None,
        timeout: int = 5,
        retries: int = 3,
        cache_ttl: int = 300,
        concurrency: int = 100,
        doh_enabled: bool = False,
        doh_server: str = "https://cloudflare-dns.com/dns-query",
    ) -> None:
        """Initialise the resolver.

        Args:
            nameservers: Custom DNS server IPs (defaults to system resolvers).
            timeout: Query timeout in seconds.
            retries: Number of retry attempts per query.
            cache_ttl: Default cache TTL in seconds.
            concurrency: Max simultaneous DNS queries.
            doh_enabled: Use DNS-over-HTTPS instead of traditional DNS.
            doh_server: DoH server URL (e.g. Cloudflare or Google endpoint).
        """
        self._nameservers = nameservers or ["8.8.8.8", "8.8.4.4", "1.1.1.1"]
        self._timeout = timeout
        self._retries = retries
        self._cache_ttl = cache_ttl
        self._concurrency = concurrency
        self._doh_enabled = doh_enabled
        self._doh_server = doh_server
        self._resolver: Optional[Any] = None
        self._cache: Dict[str, DNSCacheEntry] = {}
        self._sem: Optional[asyncio.Semaphore] = None
        self._doh_session: Optional[Any] = None

    async def __aenter__(self) -> "AsyncDNSResolver":
        await self._init()
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._doh_session is not None:
            try:
                await self._doh_session.close()
            except Exception:  # noqa: BLE001
                pass
            self._doh_session = None

    async def _init(self) -> None:
        """Initialise the underlying aiodns resolver, DoH session, and semaphore."""
        self._sem = asyncio.Semaphore(self._concurrency)
        if self._doh_enabled and _AIOHTTP_AVAILABLE:
            import aiohttp
            self._doh_session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self._timeout)
            )
            logger.debug("DNS-over-HTTPS enabled: %s", self._doh_server)
        elif not self._doh_enabled and _AIODNS_AVAILABLE:
            loop = asyncio.get_event_loop()
            self._resolver = aiodns.DNSResolver(
                loop=loop,
                nameservers=self._nameservers,
                timeout=self._timeout,
            )
        else:
            logger.warning(
                "aiodns not installed — DNS resolution will use asyncio fallback."
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def resolve(
        self, domain: str, record_type: str = "A"
    ) -> List[str]:
        """Resolve *domain* for the given DNS *record_type*.

        Args:
            domain: The domain name to query.
            record_type: DNS record type string (e.g. ``"A"``, ``"MX"``).

        Returns:
            List of string representations of the DNS records.
        """
        if self._sem is None:
            await self._init()

        record_type = record_type.upper()
        key = _cache_key(domain, record_type)

        entry = self._cache.get(key)
        if entry and not entry.expired:
            return entry.records

        for attempt in range(self._retries):
            try:
                records = await self._do_resolve(domain, record_type)
                self._cache[key] = DNSCacheEntry(records, self._cache_ttl)
                return records
            except Exception as exc:  # noqa: BLE001
                if attempt == self._retries - 1:
                    logger.debug(
                        "DNS %s query for %s failed: %s", record_type, domain, exc
                    )
                    return []
                await asyncio.sleep(0.2 * (attempt + 1))
        return []

    async def resolve_all(
        self, domain: str
    ) -> Dict[str, List[str]]:
        """Resolve *domain* for all common record types.

        Args:
            domain: Domain name to query.

        Returns:
            Dict mapping record type to list of records.
        """
        record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV"]
        tasks = {rt: asyncio.create_task(self.resolve(domain, rt)) for rt in record_types}
        results: Dict[str, List[str]] = {}
        for rt, task in tasks.items():
            results[rt] = await task
        return results

    async def bulk_resolve(
        self, domains: List[str], record_type: str = "A"
    ) -> Dict[str, List[str]]:
        """Resolve many *domains* concurrently for the same *record_type*.

        Args:
            domains: List of domain names.
            record_type: DNS record type.

        Returns:
            Dict mapping each domain to its records.
        """
        assert self._sem is not None

        async def _one(domain: str) -> Tuple[str, List[str]]:
            async with self._sem:  # type: ignore[union-attr]
                records = await self.resolve(domain, record_type)
                return domain, records

        pairs = await asyncio.gather(*[_one(d) for d in domains])
        return dict(pairs)

    async def detect_wildcard(self, domain: str) -> bool:
        """Return ``True`` if *domain* has wildcard DNS configured.

        Queries a random non-existent subdomain to check for wildcard response.

        Args:
            domain: Base domain to check.

        Returns:
            Boolean indicating wildcard presence.
        """
        import random
        import string
        rand = "".join(random.choices(string.ascii_lowercase, k=12))
        test_domain = f"{rand}.{domain}"
        records = await self.resolve(test_domain, "A")
        return bool(records)

    # ------------------------------------------------------------------
    # Internal resolution logic
    # ------------------------------------------------------------------

    async def _do_resolve(self, domain: str, record_type: str) -> List[str]:
        """Perform the actual DNS query.

        Routes to DoH when ``doh_enabled`` is set, otherwise uses aiodns or
        the asyncio socket fallback.

        Args:
            domain: Domain to query.
            record_type: Record type string.

        Returns:
            List of string DNS records.
        """
        if self._doh_enabled and self._doh_session is not None:
            return await self._doh_resolve(domain, record_type)
        if _AIODNS_AVAILABLE and self._resolver:
            return await self._aiodns_resolve(domain, record_type)
        return await self._socket_resolve(domain)

    async def _aiodns_resolve(self, domain: str, record_type: str) -> List[str]:
        """Use aiodns to resolve *domain*."""
        assert self._resolver is not None
        result = await self._resolver.query(domain, record_type)
        return self._format_records(result, record_type)

    async def _doh_resolve(self, domain: str, record_type: str) -> List[str]:
        """Resolve *domain* using DNS-over-HTTPS.

        Sends a JSON-format DoH query to the configured DoH server.

        Args:
            domain: Domain name to query.
            record_type: DNS record type string.

        Returns:
            List of answer strings from the DoH response.
        """
        assert self._doh_session is not None
        params = {"name": domain, "type": record_type}
        headers = {"Accept": "application/dns-json"}
        try:
            async with self._doh_session.get(
                self._doh_server, params=params, headers=headers
            ) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json(content_type=None)
                answers = data.get("Answer", [])
                return [str(ans.get("data", "")) for ans in answers if ans.get("data")]
        except Exception as exc:  # noqa: BLE001
            logger.debug("DoH query %s %s failed: %s", record_type, domain, exc)
            return []

    async def _socket_resolve(self, domain: str) -> List[str]:
        """Fallback resolver using :func:`asyncio.get_event_loop().getaddrinfo`."""
        loop = asyncio.get_event_loop()
        infos = await loop.getaddrinfo(domain, None)
        return list({info[4][0] for info in infos})

    @staticmethod
    def _format_records(result: Any, record_type: str) -> List[str]:
        """Convert aiodns result objects to plain strings.

        Args:
            result: Raw aiodns result (list or single object).
            record_type: DNS record type string.

        Returns:
            List of string representations.
        """
        out: List[str] = []
        items = result if isinstance(result, list) else [result]
        for item in items:
            if record_type == "A":
                out.append(item.host)
            elif record_type == "AAAA":
                out.append(item.host)
            elif record_type == "CNAME":
                out.append(item.cname)
            elif record_type == "MX":
                out.append(f"{item.priority} {item.host}")
            elif record_type == "NS":
                out.append(item.host)
            elif record_type == "TXT":
                text = item.text
                if isinstance(text, (bytes, bytearray)):
                    text = text.decode("utf-8", errors="replace")
                out.append(text)
            elif record_type == "SOA":
                out.append(
                    f"{item.nsname} {item.hostmaster} serial={item.serial}"
                )
            elif record_type == "SRV":
                out.append(f"{item.priority} {item.weight} {item.port} {item.host}")
            else:
                out.append(str(item))
        return out
