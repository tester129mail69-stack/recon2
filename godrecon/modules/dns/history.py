"""DNS history and passive DNS module for GODRECON.

Queries public passive DNS APIs to retrieve historical DNS records for a
target domain, helping detect recent changes that may indicate compromise.
"""

from __future__ import annotations

from typing import Any, Dict, List

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# Public passive DNS sources that require no API key
_PASSIVE_DNS_SOURCES: List[Dict[str, str]] = [
    {
        "name": "hackertarget",
        "url": "https://api.hackertarget.com/hostsearch/?q={domain}",
        "format": "text",
    },
    {
        "name": "rapiddns",
        "url": "https://rapiddns.io/subdomain/{domain}?full=1&down=1",
        "format": "text",
    },
]


class DNSHistoryChecker:
    """Query passive DNS sources for historical DNS records.

    Uses the existing :class:`~godrecon.utils.http_client.AsyncHTTPClient`
    to fetch data from free passive DNS APIs.

    Example::

        async with AsyncHTTPClient() as http:
            checker = DNSHistoryChecker(http)
            result = await checker.check("example.com")
    """

    def __init__(self, http_client: AsyncHTTPClient) -> None:
        """Initialise the checker.

        Args:
            http_client: Configured HTTP client instance.
        """
        self._http = http_client

    async def check(self, domain: str) -> Dict[str, Any]:
        """Query passive DNS sources for *domain*.

        Args:
            domain: Target domain.

        Returns:
            Dict with ``sources`` (per-source results) and ``records``
            (deduplicated list of historical records/subdomains found).
        """
        import asyncio

        source_results: Dict[str, Any] = {}
        all_records: List[str] = []

        tasks = {
            src["name"]: asyncio.create_task(self._query_source(src, domain))
            for src in _PASSIVE_DNS_SOURCES
        }
        for name, task in tasks.items():
            try:
                records = await task
                source_results[name] = {"records": records, "count": len(records)}
                all_records.extend(records)
            except Exception as exc:  # noqa: BLE001
                logger.debug("Passive DNS source %s failed: %s", name, exc)
                source_results[name] = {"records": [], "count": 0, "error": str(exc)}

        unique_records = list(dict.fromkeys(all_records))
        return {
            "sources": source_results,
            "records": unique_records,
            "count": len(unique_records),
        }

    async def _query_source(self, source: Dict[str, str], domain: str) -> List[str]:
        """Query a single passive DNS source.

        Args:
            source: Source descriptor dict with ``name``, ``url``, ``format``.
            domain: Target domain.

        Returns:
            List of record/hostname strings found.
        """
        url = source["url"].format(domain=domain)
        try:
            resp = await self._http.get(url)
            if resp.get("status") != 200:
                return []
            body = resp.get("body", "")
            return self._parse_response(body, source["format"], domain)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Passive DNS %s query failed: %s", source["name"], exc)
            return []

    @staticmethod
    def _parse_response(body: str, fmt: str, domain: str) -> List[str]:
        """Parse a passive DNS API response into a list of records.

        Args:
            body: HTTP response body.
            fmt: Response format hint (``"text"`` or ``"json"``).
            domain: Domain being queried (for filtering).

        Returns:
            List of subdomain/hostname strings.
        """
        records: List[str] = []
        if not body:
            return records

        if fmt == "text":
            for line in body.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # hackertarget returns "sub.domain.com,1.2.3.4"
                host = line.split(",")[0].strip().lower()
                if host and (host.endswith(f".{domain}") or host == domain):
                    records.append(host)
        return records
