"""Web Archive additional sources subdomain module."""

from __future__ import annotations

import json
from typing import Set
from urllib.parse import urlparse

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.modules.subdomains.sources.base import SubdomainSource


class WebArchiveSource(SubdomainSource):
    """Discover subdomains via additional Wayback Machine CDX queries.

    Complements :class:`~godrecon.modules.subdomains.sources.wayback.WaybackSource`
    by querying with different parameters to find more results.
    No API key required.
    """

    name = "webarchive"
    description = "Additional Web Archive CDX queries"
    requires_api_key = False

    async def fetch(self, domain: str) -> Set[str]:
        """Query Wayback Machine CDX with additional filters for *domain*.

        Args:
            domain: Root domain to enumerate.

        Returns:
            Set of discovered subdomain strings.
        """
        results: Set[str] = set()
        urls = [
            (
                f"https://web.archive.org/cdx/search/cdx"
                f"?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
                f"&limit=5000&filter=statuscode:200"
            ),
        ]
        try:
            async with AsyncHTTPClient(timeout=30, retries=2) as client:
                for url in urls:
                    resp = await client.get(url)
                    if resp["status"] != 200:
                        continue
                    data = json.loads(resp["body"])
                    for row in data[1:]:
                        if not row:
                            continue
                        try:
                            host = urlparse(row[0]).hostname or ""
                        except Exception:  # noqa: BLE001
                            continue
                        host = host.lower().lstrip("*.")
                        if host.endswith(f".{domain}") or host == domain:
                            results.add(host)
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("WebArchive error: %s", exc)
        return results
