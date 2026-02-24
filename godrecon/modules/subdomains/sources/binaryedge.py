"""BinaryEdge subdomain source."""

from __future__ import annotations

import json
from typing import Set

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.modules.subdomains.sources.base import SubdomainSource


class BinaryEdgeSource(SubdomainSource):
    """Discover subdomains via the BinaryEdge API.

    Requires a BinaryEdge API key configured as ``api_keys.binaryedge``.
    """

    name = "binaryedge"
    description = "BinaryEdge subdomain enumeration API"
    requires_api_key = True
    api_key_name = "binaryedge"

    def __init__(self, api_key: str) -> None:
        """Initialise with a BinaryEdge API key.

        Args:
            api_key: BinaryEdge API key string.
        """
        super().__init__()
        self._api_key = api_key

    async def fetch(self, domain: str) -> Set[str]:
        """Query BinaryEdge for subdomains of *domain*.

        Args:
            domain: Root domain to enumerate.

        Returns:
            Set of discovered subdomain strings.
        """
        url = f"https://api.binaryedge.io/v2/query/domains/subdomain/{domain}"
        results: Set[str] = set()
        try:
            async with AsyncHTTPClient(
                timeout=30, retries=2, headers={"X-Key": self._api_key}
            ) as client:
                page = 1
                while True:
                    resp = await client.get(f"{url}?page={page}")
                    if resp["status"] != 200:
                        break
                    data = json.loads(resp["body"])
                    for event in data.get("events", []):
                        host = event.lower().rstrip(".")
                        if host.endswith(f".{domain}") or host == domain:
                            results.add(host)
                    total = data.get("total", 0)
                    page_size = data.get("pagesize", 100)
                    if page * page_size >= total:
                        break
                    page += 1
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("BinaryEdge error: %s", exc)
        return results
