"""AlienVault OTX passive DNS subdomain source."""

from __future__ import annotations

import json
from typing import Set

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.modules.subdomains.sources.base import SubdomainSource


class AlienVaultSource(SubdomainSource):
    """Discover subdomains via AlienVault OTX passive DNS API.

    Uses the public OTX API endpoint — no API key required.
    """

    name = "alienvault"
    description = "AlienVault OTX passive DNS"
    requires_api_key = False

    async def fetch(self, domain: str) -> Set[str]:
        """Query AlienVault OTX for passive DNS records of *domain*.

        Args:
            domain: Root domain to enumerate.

        Returns:
            Set of discovered subdomain strings.
        """
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        results: Set[str] = set()
        try:
            async with AsyncHTTPClient(timeout=30, retries=2) as client:
                resp = await client.get(url)
                if resp["status"] != 200:
                    return results
                data = json.loads(resp["body"])
                for entry in data.get("passive_dns", []):
                    hostname = entry.get("hostname", "").lower().lstrip("*.")
                    if hostname.endswith(f".{domain}") or hostname == domain:
                        results.add(hostname)
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("AlienVault error: %s", exc)
        return results
