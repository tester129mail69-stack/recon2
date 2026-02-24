"""Robtex subdomain source."""

from __future__ import annotations

import json
from typing import Set

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.modules.subdomains.sources.base import SubdomainSource


class RobtexSource(SubdomainSource):
    """Discover subdomains via the Robtex free API.

    Uses the public ``/pdns/forward/`` endpoint — no API key required.
    """

    name = "robtex"
    description = "Robtex passive DNS API"
    requires_api_key = False

    async def fetch(self, domain: str) -> Set[str]:
        """Query Robtex for passive DNS records of *domain*.

        Args:
            domain: Root domain to enumerate.

        Returns:
            Set of discovered subdomain strings.
        """
        url = f"https://freeapi.robtex.com/pdns/forward/{domain}"
        results: Set[str] = set()
        try:
            async with AsyncHTTPClient(timeout=30, retries=2) as client:
                resp = await client.get(url)
                if resp["status"] != 200:
                    return results
                # Robtex returns NDJSON (one JSON object per line)
                for line in resp["body"].splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    rrname = entry.get("rrname", "").lower().rstrip(".")
                    if rrname.endswith(f".{domain}") or rrname == domain:
                        results.add(rrname)
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("Robtex error: %s", exc)
        return results
