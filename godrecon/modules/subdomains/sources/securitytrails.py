"""SecurityTrails subdomain source."""

from __future__ import annotations

import json
from typing import Set

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.modules.subdomains.sources.base import SubdomainSource


class SecurityTrailsSource(SubdomainSource):
    """Discover subdomains via the SecurityTrails API.

    Requires a SecurityTrails API key configured as ``api_keys.securitytrails``.
    """

    name = "securitytrails"
    description = "SecurityTrails subdomain API"
    requires_api_key = True
    api_key_name = "securitytrails"

    def __init__(self, api_key: str) -> None:
        """Initialise with a SecurityTrails API key.

        Args:
            api_key: SecurityTrails API key string.
        """
        super().__init__()
        self._api_key = api_key

    async def fetch(self, domain: str) -> Set[str]:
        """Query SecurityTrails for subdomains of *domain*.

        Args:
            domain: Root domain to enumerate.

        Returns:
            Set of discovered subdomain strings.
        """
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        results: Set[str] = set()
        try:
            async with AsyncHTTPClient(
                timeout=30, retries=2, headers={"APIKEY": self._api_key}
            ) as client:
                resp = await client.get(url)
                if resp["status"] != 200:
                    return results
                data = json.loads(resp["body"])
                for sub in data.get("subdomains", []):
                    host = f"{sub}.{domain}".lower()
                    results.add(host)
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("SecurityTrails error: %s", exc)
        return results
