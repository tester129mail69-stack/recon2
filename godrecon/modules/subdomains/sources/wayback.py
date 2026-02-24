"""Wayback Machine (web.archive.org) subdomain source."""

from __future__ import annotations

import json
import re
from typing import Set
from urllib.parse import urlparse

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.modules.subdomains.sources.base import SubdomainSource


class WaybackSource(SubdomainSource):
    """Discover subdomains from Wayback Machine CDX API.

    Queries ``web.archive.org`` for all crawled URLs under ``*.domain``.
    No API key required.
    """

    name = "wayback"
    description = "Wayback Machine CDX API (web.archive.org)"
    requires_api_key = False

    async def fetch(self, domain: str) -> Set[str]:
        """Query Wayback Machine CDX for subdomains of *domain*.

        Args:
            domain: Root domain to enumerate.

        Returns:
            Set of discovered subdomain strings.
        """
        url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url=*.{domain}&output=json&fl=original&collapse=urlkey&limit=10000"
        )
        results: Set[str] = set()
        try:
            async with AsyncHTTPClient(timeout=30, retries=2) as client:
                resp = await client.get(url)
                if resp["status"] != 200:
                    return results
                data = json.loads(resp["body"])
                # data[0] is the header row ["original"]
                for row in data[1:]:
                    if not row:
                        continue
                    original_url = row[0]
                    try:
                        host = urlparse(original_url).hostname or ""
                    except Exception:  # noqa: BLE001
                        continue
                    host = host.lower().lstrip("*.")
                    if host.endswith(f".{domain}") or host == domain:
                        results.add(host)
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("Wayback error: %s", exc)
        return results
