"""BufferOver subdomain source."""

from __future__ import annotations

import json
from typing import Set

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.modules.subdomains.sources.base import SubdomainSource


class BufferOverSource(SubdomainSource):
    """Discover subdomains via the BufferOver.run DNS API.

    Uses the public API endpoint — no API key required.
    """

    name = "bufferover"
    description = "BufferOver.run passive DNS"
    requires_api_key = False

    async def fetch(self, domain: str) -> Set[str]:
        """Query BufferOver for DNS records containing *domain*.

        Args:
            domain: Root domain to enumerate.

        Returns:
            Set of discovered subdomain strings.
        """
        url = f"https://dns.bufferover.run/dns?q=.{domain}"
        results: Set[str] = set()
        try:
            async with AsyncHTTPClient(timeout=30, retries=2) as client:
                resp = await client.get(url, headers={"Accept": "application/json"})
                if resp["status"] != 200:
                    return results
                data = json.loads(resp["body"])
                for record_list in (data.get("FDNS_A", []), data.get("RDNS", [])):
                    for record in record_list:
                        # Format: "IP,hostname"
                        parts = record.split(",")
                        host = parts[-1].lower().strip().rstrip(".")
                        if host.endswith(f".{domain}") or host == domain:
                            results.add(host)
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("BufferOver error: %s", exc)
        return results
