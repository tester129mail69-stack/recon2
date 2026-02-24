"""ThreatCrowd subdomain source."""

from __future__ import annotations

import json
from typing import Set

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.modules.subdomains.sources.base import SubdomainSource


class ThreatCrowdSource(SubdomainSource):
    """Discover subdomains via the ThreatCrowd API.

    Uses the public domain search endpoint — no API key required.
    """

    name = "threatcrowd"
    description = "ThreatCrowd domain search API"
    requires_api_key = False

    async def fetch(self, domain: str) -> Set[str]:
        """Query ThreatCrowd for subdomains of *domain*.

        Args:
            domain: Root domain to enumerate.

        Returns:
            Set of discovered subdomain strings.
        """
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
        results: Set[str] = set()
        try:
            async with AsyncHTTPClient(timeout=30, retries=2) as client:
                resp = await client.get(url)
                if resp["status"] != 200:
                    return results
                data = json.loads(resp["body"])
                for host in data.get("subdomains", []):
                    host = host.lower().lstrip("*.")
                    if host.endswith(f".{domain}") or host == domain:
                        results.add(host)
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("ThreatCrowd error: %s", exc)
        return results
