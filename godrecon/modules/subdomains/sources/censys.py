"""Censys subdomain source."""

from __future__ import annotations

import json
from typing import Set

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.modules.subdomains.sources.base import SubdomainSource


class CensysSource(SubdomainSource):
    """Discover subdomains via the Censys Search API.

    Requires a Censys API ID and secret configured as
    ``api_keys.censys_id`` and ``api_keys.censys_secret``.
    """

    name = "censys"
    description = "Censys search API"
    requires_api_key = True
    api_key_name = "censys_id"

    def __init__(self, api_id: str, api_secret: str) -> None:
        """Initialise with Censys API credentials.

        Args:
            api_id: Censys API ID.
            api_secret: Censys API secret.
        """
        super().__init__()
        self._api_id = api_id
        self._api_secret = api_secret

    async def fetch(self, domain: str) -> Set[str]:
        """Query Censys for hosts matching *domain*.

        Args:
            domain: Root domain to enumerate.

        Returns:
            Set of discovered subdomain strings.
        """
        import base64
        url = "https://search.censys.io/api/v2/hosts/search"
        results: Set[str] = set()
        credentials = base64.b64encode(
            f"{self._api_id}:{self._api_secret}".encode()
        ).decode()
        try:
            async with AsyncHTTPClient(
                timeout=30,
                retries=2,
                headers={"Authorization": f"Basic {credentials}"},
            ) as client:
                cursor = None
                while True:
                    params = {"q": f"parsed.names: {domain}", "per_page": 100}
                    if cursor:
                        params["cursor"] = cursor
                    resp = await client.get(url, params=params)
                    if resp["status"] != 200:
                        break
                    data = json.loads(resp["body"])
                    for hit in data.get("result", {}).get("hits", []):
                        for name in hit.get("parsed", {}).get("names", []):
                            name = name.lower().lstrip("*.")
                            if name.endswith(f".{domain}") or name == domain:
                                results.add(name)
                    cursor = (
                        data.get("result", {})
                        .get("links", {})
                        .get("next")
                    )
                    if not cursor:
                        break
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("Censys error: %s", exc)
        return results
