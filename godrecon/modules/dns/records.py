"""DNS record resolver for GODRECON.

Resolves all standard DNS record types for a target domain concurrently using
the existing :class:`~godrecon.utils.dns_resolver.AsyncDNSResolver`.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List

from godrecon.utils.dns_resolver import AsyncDNSResolver
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# All record types to query; types not natively supported by aiodns fall back
# to a string representation via the generic resolver path.
ALL_RECORD_TYPES: List[str] = [
    "A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "SRV",
    "PTR", "CAA", "DNSKEY", "DS", "TLSA", "NAPTR", "LOC", "HINFO",
]


class DNSRecordResolver:
    """Resolve all DNS record types for a domain concurrently.

    Example::

        async with AsyncDNSResolver() as resolver:
            rec = DNSRecordResolver(resolver)
            results = await rec.resolve_all("example.com")
    """

    def __init__(self, resolver: AsyncDNSResolver) -> None:
        """Initialise with an existing :class:`AsyncDNSResolver`.

        Args:
            resolver: Configured and initialised DNS resolver instance.
        """
        self._resolver = resolver

    async def resolve_all(self, domain: str) -> Dict[str, List[str]]:
        """Resolve all DNS record types for *domain* concurrently.

        Missing record types are returned as empty lists — they do not raise
        exceptions.

        Args:
            domain: Domain name to query.

        Returns:
            Mapping of record type string to list of record strings.
        """
        tasks: Dict[str, asyncio.Task[List[str]]] = {
            rt: asyncio.create_task(self._safe_resolve(domain, rt))
            for rt in ALL_RECORD_TYPES
        }
        results: Dict[str, List[str]] = {}
        for rt, task in tasks.items():
            results[rt] = await task
        return results

    async def _safe_resolve(self, domain: str, record_type: str) -> List[str]:
        """Resolve *record_type* for *domain*, returning ``[]`` on any error.

        Args:
            domain: Domain name.
            record_type: DNS record type string.

        Returns:
            List of record strings, or empty list on failure.
        """
        try:
            return await self._resolver.resolve(domain, record_type)
        except Exception as exc:  # noqa: BLE001
            logger.debug("DNS %s for %s failed: %s", record_type, domain, exc)
            return []

    async def resolve_mx(self, domain: str) -> List[Dict[str, Any]]:
        """Return MX records with parsed priority and host fields.

        Args:
            domain: Domain name.

        Returns:
            List of dicts with ``priority`` and ``host`` keys.
        """
        raw = await self._safe_resolve(domain, "MX")
        records: List[Dict[str, Any]] = []
        for entry in raw:
            parts = entry.split(" ", 1)
            if len(parts) == 2:
                try:
                    records.append({"priority": int(parts[0]), "host": parts[1]})
                except ValueError:
                    records.append({"priority": 0, "host": entry})
            else:
                records.append({"priority": 0, "host": entry})
        return sorted(records, key=lambda r: r["priority"])
