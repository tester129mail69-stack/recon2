"""URLScan.io subdomain source."""

from __future__ import annotations

import json
from typing import Set

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.modules.subdomains.sources.base import SubdomainSource


class URLScanSource(SubdomainSource):
    """Discover subdomains via the URLScan.io search API.

    Uses the public search endpoint — no API key required.
    """

    name = "urlscan"
    description = "URLScan.io domain search API"
    requires_api_key = False

    async def fetch(self, domain: str) -> Set[str]:
        """Query URLScan.io for results matching *domain*.

        Args:
            domain: Root domain to enumerate.

        Returns:
            Set of discovered subdomain strings.
        """
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10000"
        results: Set[str] = set()
        try:
            async with AsyncHTTPClient(timeout=30, retries=2) as client:
                resp = await client.get(url, headers={"Accept": "application/json"})
                if resp["status"] != 200:
                    return results
                data = json.loads(resp["body"])
                for result in data.get("results", []):
                    # page.domain and page.ptr
                    page = result.get("page", {})
                    for field in ("domain", "ptr"):
                        host = page.get(field, "").lower()
                        if host.endswith(f".{domain}") or host == domain:
                            results.add(host)
                    # task.domain
                    task = result.get("task", {})
                    host = task.get("domain", "").lower()
                    if host.endswith(f".{domain}") or host == domain:
                        results.add(host)
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("URLScan error: %s", exc)
        return results
