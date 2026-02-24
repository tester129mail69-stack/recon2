"""HackerTarget host search subdomain source."""

from __future__ import annotations

from typing import Set

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.modules.subdomains.sources.base import SubdomainSource


class HackerTargetSource(SubdomainSource):
    """Discover subdomains via the HackerTarget hostsearch API.

    Returns plain-text ``host,ip`` pairs — no API key required.
    """

    name = "hackertarget"
    description = "HackerTarget hostsearch API"
    requires_api_key = False

    async def fetch(self, domain: str) -> Set[str]:
        """Query HackerTarget for hosts matching *domain*.

        Args:
            domain: Root domain to enumerate.

        Returns:
            Set of discovered subdomain strings.
        """
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        results: Set[str] = set()
        try:
            async with AsyncHTTPClient(timeout=30, retries=2) as client:
                resp = await client.get(url)
                if resp["status"] != 200:
                    return results
                body = resp["body"]
                if "error" in body.lower() and len(body) < 200:
                    return results
                for line in body.splitlines():
                    host = line.split(",")[0].strip().lower()
                    if host.endswith(f".{domain}") or host == domain:
                        results.add(host)
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("HackerTarget error: %s", exc)
        return results
