"""VirusTotal subdomain source."""

from __future__ import annotations

import json
from typing import Optional, Set

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.modules.subdomains.sources.base import SubdomainSource


class VirusTotalSource(SubdomainSource):
    """Discover subdomains via the VirusTotal v3 API.

    Requires a VirusTotal API key configured as ``api_keys.virustotal``.
    """

    name = "virustotal"
    description = "VirusTotal v3 domain subdomains API"
    requires_api_key = True
    api_key_name = "virustotal"

    def __init__(self, api_key: str) -> None:
        """Initialise with a VirusTotal API key.

        Args:
            api_key: VirusTotal API key string.
        """
        super().__init__()
        self._api_key = api_key

    async def fetch(self, domain: str) -> Set[str]:
        """Query VirusTotal for subdomains of *domain*.

        Args:
            domain: Root domain to enumerate.

        Returns:
            Set of discovered subdomain strings.
        """
        results: Set[str] = set()
        cursor: Optional[str] = None
        try:
            async with AsyncHTTPClient(
                timeout=30, retries=2, headers={"x-apikey": self._api_key}
            ) as client:
                while True:
                    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
                    if cursor:
                        url += f"&cursor={cursor}"
                    resp = await client.get(url)
                    if resp["status"] != 200:
                        break
                    data = json.loads(resp["body"])
                    for item in data.get("data", []):
                        host = item.get("id", "").lower()
                        if host.endswith(f".{domain}") or host == domain:
                            results.add(host)
                    cursor = data.get("meta", {}).get("cursor")
                    if not cursor:
                        break
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("VirusTotal error: %s", exc)
        return results
