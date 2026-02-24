"""AnubisDB subdomain source."""

from __future__ import annotations

import json
from typing import Set

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.modules.subdomains.sources.base import SubdomainSource


class AnubisSource(SubdomainSource):
    """Discover subdomains via the AnubisDB (jldc.me) API.

    Uses the public API endpoint — no API key required.
    """

    name = "anubis"
    description = "AnubisDB subdomain lookup (jldc.me)"
    requires_api_key = False

    async def fetch(self, domain: str) -> Set[str]:
        """Query AnubisDB for subdomains of *domain*.

        Args:
            domain: Root domain to enumerate.

        Returns:
            Set of discovered subdomain strings.
        """
        url = f"https://jldc.me/anubis/subdomains/{domain}"
        results: Set[str] = set()
        try:
            async with AsyncHTTPClient(timeout=30, retries=2) as client:
                resp = await client.get(url)
                if resp["status"] != 200:
                    return results
                data = json.loads(resp["body"])
                for host in data:
                    host = host.lower().strip().lstrip("*.")
                    if host.endswith(f".{domain}") or host == domain:
                        results.add(host)
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("AnubisDB error: %s", exc)
        return results
