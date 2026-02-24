"""Hunter.io subdomain source."""

from __future__ import annotations

import json
from typing import Set

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.modules.subdomains.sources.base import SubdomainSource


class HunterSource(SubdomainSource):
    """Discover subdomains via the Hunter.io domain search API.

    Requires a Hunter.io API key configured as ``api_keys.hunter``.
    """

    name = "hunter"
    description = "Hunter.io domain search API"
    requires_api_key = True
    api_key_name = "hunter"

    def __init__(self, api_key: str) -> None:
        """Initialise with a Hunter.io API key.

        Args:
            api_key: Hunter.io API key string.
        """
        super().__init__()
        self._api_key = api_key

    async def fetch(self, domain: str) -> Set[str]:
        """Query Hunter.io for email/domain data for *domain*.

        Args:
            domain: Root domain to enumerate.

        Returns:
            Set of discovered subdomain strings.
        """
        url = (
            f"https://api.hunter.io/v2/domain-search"
            f"?domain={domain}&api_key={self._api_key}&limit=100"
        )
        results: Set[str] = set()
        try:
            async with AsyncHTTPClient(timeout=30, retries=2) as client:
                resp = await client.get(url)
                if resp["status"] != 200:
                    return results
                data = json.loads(resp["body"])
                # Hunter returns emails; extract unique domain parts
                for email_entry in data.get("data", {}).get("emails", []):
                    email = email_entry.get("value", "")
                    if "@" in email:
                        host = email.split("@")[1].lower()
                        if host.endswith(f".{domain}") or host == domain:
                            results.add(host)
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("Hunter error: %s", exc)
        return results
