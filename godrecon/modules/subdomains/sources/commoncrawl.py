"""CommonCrawl subdomain source."""

from __future__ import annotations

import json
from typing import Set
from urllib.parse import urlparse

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.modules.subdomains.sources.base import SubdomainSource


class CommonCrawlSource(SubdomainSource):
    """Discover subdomains via the CommonCrawl index API.

    Queries the latest CommonCrawl index for URLs matching ``*.domain`` —
    no API key required.
    """

    name = "commoncrawl"
    description = "CommonCrawl index API"
    requires_api_key = False

    _INDEX_URL = "https://index.commoncrawl.org/collinfo.json"

    async def fetch(self, domain: str) -> Set[str]:
        """Query the CommonCrawl index for subdomains of *domain*.

        Args:
            domain: Root domain to enumerate.

        Returns:
            Set of discovered subdomain strings.
        """
        results: Set[str] = set()
        try:
            async with AsyncHTTPClient(timeout=30, retries=2) as client:
                # Discover the latest index API endpoint
                idx_resp = await client.get(self._INDEX_URL)
                if idx_resp["status"] != 200:
                    return results
                indexes = json.loads(idx_resp["body"])
                if not indexes:
                    return results
                # Use only the most recent index to avoid too many requests
                api_url = indexes[0].get("cdx-api", "")
                if not api_url:
                    return results

                search_url = (
                    f"{api_url}?url=*.{domain}&output=json"
                    "&fl=url&limit=5000&collapse=urlkey"
                )
                resp = await client.get(search_url)
                if resp["status"] != 200:
                    return results
                for line in resp["body"].splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    url_str = entry.get("url", "")
                    try:
                        host = urlparse(url_str).hostname or ""
                    except Exception:  # noqa: BLE001
                        continue
                    host = host.lower().lstrip("*.")
                    if host.endswith(f".{domain}") or host == domain:
                        results.add(host)
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("CommonCrawl error: %s", exc)
        return results
