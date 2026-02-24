"""DuckDuckGo search scraping subdomain source."""

from __future__ import annotations

import re
from typing import Set

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.modules.subdomains.sources.base import SubdomainSource

_HOST_RE = re.compile(r'([\w\-]+(?:\.[\w\-]+)*\.[a-zA-Z]{2,})', re.IGNORECASE)


class DuckDuckGoSource(SubdomainSource):
    """Discover subdomains via DuckDuckGo search.

    Uses the DuckDuckGo HTML search endpoint — no API key required.
    Note: DuckDuckGo does not paginate results in the same way as other engines.
    """

    name = "duckduckgo"
    description = "DuckDuckGo site:*.domain search"
    requires_api_key = False
    rate_limit = 2.0

    async def fetch(self, domain: str) -> Set[str]:
        """Query DuckDuckGo for subdomains of *domain*.

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
                url = f"https://html.duckduckgo.com/html/?q=site%3A*.{domain}"
                resp = await client.get(
                    url,
                    headers={
                        "Accept-Language": "en-US,en;q=0.9",
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                )
                if resp["status"] not in (200, 301, 302):
                    return results
                body = resp["body"]
                suffix = f".{domain}"
                for match in _HOST_RE.finditer(body):
                    host = match.group(1).lower()
                    if host.endswith(suffix) or host == domain:
                        results.add(host)
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("DuckDuckGo error: %s", exc)
        return results
