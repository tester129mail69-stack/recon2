"""Direct Certificate Transparency log query subdomain source."""

from __future__ import annotations

import json
from typing import Set

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.modules.subdomains.sources.base import SubdomainSource


class CTLogsSource(SubdomainSource):
    """Discover subdomains by directly querying multiple CT log APIs.

    Queries several CT log transparency providers beyond crt.sh.
    No API key required.
    """

    name = "ct_logs"
    description = "Direct Certificate Transparency log queries"
    requires_api_key = False

    async def fetch(self, domain: str) -> Set[str]:
        """Query multiple CT log sources for certificates issued for *domain*.

        Args:
            domain: Root domain to enumerate.

        Returns:
            Set of discovered subdomain strings.
        """
        results: Set[str] = set()
        try:
            async with AsyncHTTPClient(timeout=30, retries=2) as client:
                # Facebook CT log search
                fb_url = (
                    f"https://developers.facebook.com/tools/ct/search/"
                    f"?domain={domain}"
                )
                # Google Transparency Report
                google_url = (
                    f"https://transparencyreport.google.com/transparencyreport/api/v3/"
                    f"httpsreport/ct/certsearch/page?include_expired=true"
                    f"&include_subdomains=true&domain={domain}"
                )
                # crt.sh LIKE query (different pattern)
                crtsh_url = f"https://crt.sh/?q={domain}&output=json"

                for url in (crtsh_url,):
                    resp = await client.get(url)
                    if resp["status"] != 200:
                        continue
                    try:
                        data = json.loads(resp["body"])
                    except json.JSONDecodeError:
                        continue
                    for entry in data:
                        for field in ("name_value", "common_name"):
                            value = entry.get(field, "")
                            for name in value.splitlines():
                                name = name.strip().lstrip("*.")
                                if name.endswith(f".{domain}") or name == domain:
                                    results.add(name.lower())
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("CT logs error: %s", exc)
        return results
