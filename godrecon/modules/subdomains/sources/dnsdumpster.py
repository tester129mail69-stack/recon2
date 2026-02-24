"""DNSDumpster subdomain source (HTML scraping)."""

from __future__ import annotations

import re
from typing import Set

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.modules.subdomains.sources.base import SubdomainSource

_TD_RE = re.compile(r'<td[^>]*>([\w\-\.]+)</td>', re.IGNORECASE)


class DNSDumpsterSource(SubdomainSource):
    """Discover subdomains by scraping DNSDumpster.

    Submits a POST form and parses the resulting HTML — no API key required.
    """

    name = "dnsdumpster"
    description = "DNSDumpster subdomain lookup (web scraping)"
    requires_api_key = False

    _BASE_URL = "https://dnsdumpster.com/"

    async def fetch(self, domain: str) -> Set[str]:
        """Scrape DNSDumpster for subdomains of *domain*.

        Args:
            domain: Root domain to enumerate.

        Returns:
            Set of discovered subdomain strings.
        """
        results: Set[str] = set()
        try:
            async with AsyncHTTPClient(timeout=30, retries=2) as client:
                # First, get the CSRF token
                resp = await client.get(self._BASE_URL)
                if resp["status"] != 200:
                    return results
                csrf_match = re.search(
                    r'name=["\']csrfmiddlewaretoken["\'] value=["\']([^"\']+)["\']',
                    resp["body"],
                )
                if not csrf_match:
                    return results
                csrf_token = csrf_match.group(1)
                cookie_header = resp["headers"].get(
                    "Set-Cookie", resp["headers"].get("set-cookie", "")
                )
                # Extract csrftoken value
                csrftoken_match = re.search(r'csrftoken=([^;]+)', cookie_header)
                csrftoken = csrftoken_match.group(1) if csrftoken_match else csrf_token

                post_resp = await client.post(
                    self._BASE_URL,
                    data={"csrfmiddlewaretoken": csrf_token, "targetip": domain, "user": "free"},
                    headers={
                        "Referer": self._BASE_URL,
                        "Cookie": f"csrftoken={csrftoken}",
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                )
                if post_resp["status"] not in (200, 302):
                    return results
                body = post_resp["body"]
                # Extract hostnames from table cells
                suffix = f".{domain}"
                for match in _TD_RE.finditer(body):
                    host = match.group(1).lower().rstrip(".")
                    if host.endswith(suffix) or host == domain:
                        results.add(host)
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("DNSDumpster error: %s", exc)
        return results
