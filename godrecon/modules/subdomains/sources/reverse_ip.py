"""Reverse IP lookup subdomain source."""

from __future__ import annotations

import re
from typing import Set

from godrecon.utils.dns_resolver import AsyncDNSResolver
from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.modules.subdomains.sources.base import SubdomainSource

_HOST_RE = re.compile(r'([\w\-\.]+\.[a-zA-Z]{2,})', re.IGNORECASE)


class ReverseIPSource(SubdomainSource):
    """Discover subdomains via reverse IP lookup (co-hosted domains).

    Resolves the target domain to its IP(s), then performs reverse IP lookups
    to find all other domains hosted on the same IP address.
    No API key required.
    """

    name = "reverse_ip"
    description = "Reverse IP lookup for co-hosted domains"
    requires_api_key = False

    async def fetch(self, domain: str) -> Set[str]:
        """Perform reverse IP lookup for *domain*.

        Args:
            domain: Root domain to enumerate.

        Returns:
            Set of discovered subdomain strings.
        """
        results: Set[str] = set()
        try:
            async with AsyncDNSResolver() as resolver:
                a_records = await resolver.resolve(domain, "A")
                if not a_records:
                    return results

                async with AsyncHTTPClient(timeout=30, retries=2) as client:
                    for ip in a_records[:3]:  # Limit to first 3 IPs
                        url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
                        resp = await client.get(url)
                        if resp["status"] != 200:
                            continue
                        body = resp["body"]
                        if "error" in body.lower() and len(body) < 200:
                            continue
                        for line in body.splitlines():
                            host = line.strip().lower()
                            if host.endswith(f".{domain}") or host == domain:
                                results.add(host)
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("Reverse IP error: %s", exc)
        return results
