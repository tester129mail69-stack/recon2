"""crt.sh — Certificate Transparency log source."""

from __future__ import annotations

import json
import re
from typing import Set

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.modules.subdomains.sources.base import SubdomainSource

_SUBDOMAIN_RE = re.compile(r"^[\w\.\-]+$")


class CrtShSource(SubdomainSource):
    """Fetch subdomains from crt.sh certificate transparency logs.

    Uses the public JSON API — no API key required.
    """

    name = "crt.sh"
    description = "Certificate Transparency logs via crt.sh"
    requires_api_key = False

    async def fetch(self, domain: str) -> Set[str]:
        """Query crt.sh for certificate entries matching *domain*.

        Args:
            domain: Root domain to search.

        Returns:
            Set of discovered subdomain strings.
        """
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        results: Set[str] = set()
        try:
            async with AsyncHTTPClient(timeout=30, retries=2) as client:
                resp = await client.get(url)
                if resp["status"] != 200:
                    return results
                data = json.loads(resp["body"])
                for entry in data:
                    for field in ("name_value", "common_name"):
                        value = entry.get(field, "")
                        for name in value.splitlines():
                            name = name.strip().lstrip("*.")
                            if name.endswith(f".{domain}") or name == domain:
                                if _SUBDOMAIN_RE.match(name):
                                    results.add(name.lower())
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("crt.sh error: %s", exc)
        return results
