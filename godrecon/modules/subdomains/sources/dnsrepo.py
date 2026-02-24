"""DNSRepo subdomain source (HTML scraping)."""

from __future__ import annotations

import re
from typing import Set

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.modules.subdomains.sources.base import SubdomainSource

_HOST_RE = re.compile(r'>([\w\-\.]+\.[a-zA-Z]{2,})<', re.IGNORECASE)


class DNSRepoSource(SubdomainSource):
    """Discover subdomains by scraping DNSRepo.

    Parses HTML results — no API key required.
    """

    name = "dnsrepo"
    description = "DNSRepo subdomain lookup (HTML scraping)"
    requires_api_key = False

    async def fetch(self, domain: str) -> Set[str]:
        """Scrape DNSRepo for subdomains of *domain*.

        Args:
            domain: Root domain to enumerate.

        Returns:
            Set of discovered subdomain strings.
        """
        url = f"https://dnsrepo.noc.org/?domain={domain}"
        results: Set[str] = set()
        try:
            async with AsyncHTTPClient(timeout=30, retries=2) as client:
                resp = await client.get(url)
                if resp["status"] != 200:
                    return results
                body = resp["body"]
                suffix = f".{domain}"
                for match in _HOST_RE.finditer(body):
                    host = match.group(1).lower()
                    if host.endswith(suffix) or host == domain:
                        results.add(host)
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("DNSRepo error: %s", exc)
        return results
