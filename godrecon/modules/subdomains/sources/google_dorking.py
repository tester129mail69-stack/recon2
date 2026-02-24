"""Google dorking subdomain source."""

from __future__ import annotations

import re
from typing import Set

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.modules.subdomains.sources.base import SubdomainSource

_HOST_RE = re.compile(r'([\w\-]+(?:\.[\w\-]+)*\.[a-zA-Z]{2,})', re.IGNORECASE)


class GoogleDorkingSource(SubdomainSource):
    """Discover subdomains by scraping Google search results.

    Uses ``site:*.domain`` dork queries — no API key required.
    Note: May be rate-limited or blocked by Google.
    """

    name = "google_dorking"
    description = "Google site:*.domain dorking"
    requires_api_key = False
    rate_limit = 2.0

    async def fetch(self, domain: str) -> Set[str]:
        """Query Google search for subdomains of *domain*.

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
                for start in range(0, 100, 10):
                    url = (
                        f"https://www.google.com/search"
                        f"?q=site%3A*.{domain}&start={start}&num=10"
                    )
                    resp = await client.get(
                        url,
                        headers={
                            "Accept-Language": "en-US,en;q=0.9",
                        },
                    )
                    if resp["status"] not in (200, 301, 302):
                        break
                    body = resp["body"]
                    if "captcha" in body.lower() or "unusual traffic" in body.lower():
                        self.logger.debug("Google blocked (CAPTCHA) for %s", domain)
                        break
                    suffix = f".{domain}"
                    for match in _HOST_RE.finditer(body):
                        host = match.group(1).lower()
                        if host.endswith(suffix) or host == domain:
                            results.add(host)
                    # Stop if no results found
                    if "did not match any documents" in body:
                        break
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("Google dorking error: %s", exc)
        return results
