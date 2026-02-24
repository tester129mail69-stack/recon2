"""Bing dorking subdomain source."""

from __future__ import annotations

import re
from typing import Set

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.modules.subdomains.sources.base import SubdomainSource

_HOST_RE = re.compile(r'([\w\-]+(?:\.[\w\-]+)*\.[a-zA-Z]{2,})', re.IGNORECASE)


class BingDorkingSource(SubdomainSource):
    """Discover subdomains by scraping Bing search results.

    Uses ``site:*.domain`` dork queries — no API key required.
    """

    name = "bing_dorking"
    description = "Bing site:*.domain dorking"
    requires_api_key = False
    rate_limit = 1.5

    async def fetch(self, domain: str) -> Set[str]:
        """Query Bing search for subdomains of *domain*.

        Args:
            domain: Root domain to enumerate.

        Returns:
            Set of discovered subdomain strings.
        """
        results: Set[str] = set()
        try:
            async with AsyncHTTPClient(
                timeout=30, retries=1, rate_limit=self.rate_limit
            ) as client:
                for first in range(1, 200, 10):
                    url = (
                        f"https://www.bing.com/search"
                        f"?q=site%3A*.{domain}&first={first}"
                    )
                    resp = await client.get(
                        url,
                        headers={"Accept-Language": "en-US,en;q=0.9"},
                    )
                    if resp["status"] not in (200, 301, 302):
                        break
                    body = resp["body"]
                    suffix = f".{domain}"
                    found_in_page = False
                    for match in _HOST_RE.finditer(body):
                        host = match.group(1).lower()
                        if host.endswith(suffix) or host == domain:
                            if host not in results:
                                found_in_page = True
                            results.add(host)
                    if not found_in_page:
                        break
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("Bing dorking error: %s", exc)
        return results
