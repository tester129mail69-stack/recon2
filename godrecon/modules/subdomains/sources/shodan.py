"""Shodan subdomain source."""

from __future__ import annotations

import json
from typing import Set

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.modules.subdomains.sources.base import SubdomainSource


class ShodanSource(SubdomainSource):
    """Discover subdomains via the Shodan DNS API.

    Requires a Shodan API key configured as ``api_keys.shodan``.
    """

    name = "shodan"
    description = "Shodan DNS domain lookup API"
    requires_api_key = True
    api_key_name = "shodan"

    def __init__(self, api_key: str) -> None:
        """Initialise with a Shodan API key.

        Args:
            api_key: Shodan API key string.
        """
        super().__init__()
        self._api_key = api_key

    async def fetch(self, domain: str) -> Set[str]:
        """Query Shodan for DNS records of *domain*.

        Args:
            domain: Root domain to enumerate.

        Returns:
            Set of discovered subdomain strings.
        """
        url = f"https://api.shodan.io/dns/domain/{domain}?key={self._api_key}"
        results: Set[str] = set()
        try:
            async with AsyncHTTPClient(timeout=30, retries=2) as client:
                resp = await client.get(url)
                if resp["status"] != 200:
                    return results
                data = json.loads(resp["body"])
                for sub in data.get("subdomains", []):
                    host = f"{sub}.{domain}".lower()
                    results.add(host)
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("Shodan error: %s", exc)
        return results
