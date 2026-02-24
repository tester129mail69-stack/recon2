"""FullHunt subdomain source."""

from __future__ import annotations

import json
from typing import Set

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.modules.subdomains.sources.base import SubdomainSource


class FullHuntSource(SubdomainSource):
    """Discover subdomains via the FullHunt API.

    Requires a FullHunt API key configured as ``api_keys.fullhunt`` (custom key,
    add to config if needed).
    """

    name = "fullhunt"
    description = "FullHunt domain attack surface API"
    requires_api_key = True
    api_key_name = "fullhunt"

    def __init__(self, api_key: str) -> None:
        """Initialise with a FullHunt API key.

        Args:
            api_key: FullHunt API key string.
        """
        super().__init__()
        self._api_key = api_key

    async def fetch(self, domain: str) -> Set[str]:
        """Query FullHunt for subdomains of *domain*.

        Args:
            domain: Root domain to enumerate.

        Returns:
            Set of discovered subdomain strings.
        """
        url = f"https://fullhunt.io/api/v1/domain/{domain}/subdomains"
        results: Set[str] = set()
        try:
            async with AsyncHTTPClient(
                timeout=30, retries=2, headers={"X-API-KEY": self._api_key}
            ) as client:
                resp = await client.get(url)
                if resp["status"] != 200:
                    return results
                data = json.loads(resp["body"])
                for host in data.get("hosts", []):
                    host = host.lower().rstrip(".")
                    if host.endswith(f".{domain}") or host == domain:
                        results.add(host)
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("FullHunt error: %s", exc)
        return results
