"""CertSpotter certificate transparency subdomain source."""

from __future__ import annotations

import json
from typing import Set

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.modules.subdomains.sources.base import SubdomainSource


class CertSpotterSource(SubdomainSource):
    """Discover subdomains via the CertSpotter issuances API.

    Uses the public API endpoint — no API key required for basic queries.
    """

    name = "certspotter"
    description = "CertSpotter certificate transparency issuances API"
    requires_api_key = False

    async def fetch(self, domain: str) -> Set[str]:
        """Query CertSpotter for certificate issuances for *domain*.

        Args:
            domain: Root domain to enumerate.

        Returns:
            Set of discovered subdomain strings.
        """
        url = (
            f"https://api.certspotter.com/v1/issuances"
            f"?domain={domain}&include_subdomains=true&expand=dns_names"
        )
        results: Set[str] = set()
        try:
            async with AsyncHTTPClient(timeout=30, retries=2) as client:
                resp = await client.get(url)
                if resp["status"] != 200:
                    return results
                data = json.loads(resp["body"])
                for entry in data:
                    for name in entry.get("dns_names", []):
                        name = name.lower().lstrip("*.")
                        if name.endswith(f".{domain}") or name == domain:
                            results.add(name)
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("CertSpotter error: %s", exc)
        return results
