"""ThreatMiner subdomain source."""

from __future__ import annotations

import json
from typing import Set

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.modules.subdomains.sources.base import SubdomainSource


class ThreatMinerSource(SubdomainSource):
    """Discover subdomains via the ThreatMiner API.

    Uses the public ``/v2/domain.php`` endpoint — no API key required.
    """

    name = "threatminer"
    description = "ThreatMiner passive DNS API"
    requires_api_key = False

    async def fetch(self, domain: str) -> Set[str]:
        """Query ThreatMiner for subdomains of *domain*.

        Args:
            domain: Root domain to enumerate.

        Returns:
            Set of discovered subdomain strings.
        """
        url = f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5"
        results: Set[str] = set()
        try:
            async with AsyncHTTPClient(timeout=30, retries=1) as client:
                resp = await client.get(url)
                if resp["status"] != 200:
                    return results
                data = json.loads(resp["body"])
                for host in data.get("results", []):
                    host = host.lower().rstrip(".")
                    if host.endswith(f".{domain}") or host == domain:
                        results.add(host)
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("ThreatMiner error: %s", exc)
        return results
