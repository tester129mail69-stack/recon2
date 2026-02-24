"""RapidDNS subdomain source (HTML scraping)."""

from __future__ import annotations

import re
from typing import Set

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.modules.subdomains.sources.base import SubdomainSource

# Match subdomain links inside RapidDNS result pages
_LINK_RE = re.compile(r'href="/subdomain/([^"]+)"')
_HOST_RE = re.compile(r'<td[^>]*>([\w\.\-]+\.[a-zA-Z]{2,})</td>')


class RapidDNSSource(SubdomainSource):
    """Discover subdomains by scraping RapidDNS.

    Parses HTML results — no API key required.
    """

    name = "rapiddns"
    description = "RapidDNS subdomain lookup (HTML scraping)"
    requires_api_key = False

    async def fetch(self, domain: str) -> Set[str]:
        """Scrape RapidDNS for subdomains of *domain*.

        Args:
            domain: Root domain to enumerate.

        Returns:
            Set of discovered subdomain strings.
        """
        url = f"https://rapiddns.io/subdomain/{domain}?full=1"
        results: Set[str] = set()
        try:
            async with AsyncHTTPClient(timeout=30, retries=2) as client:
                resp = await client.get(url)
                if resp["status"] != 200:
                    return results
                body = resp["body"]
                for match in _HOST_RE.finditer(body):
                    host = match.group(1).lower().lstrip("*.")
                    if host.endswith(f".{domain}") or host == domain:
                        results.add(host)
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("RapidDNS error: %s", exc)
        return results
