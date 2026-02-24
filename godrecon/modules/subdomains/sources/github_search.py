"""GitHub code search subdomain source."""

from __future__ import annotations

import json
import re
from typing import Set

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.modules.subdomains.sources.base import SubdomainSource


class GitHubSearchSource(SubdomainSource):
    """Discover subdomains by searching GitHub code for domain mentions.

    Requires a GitHub personal access token configured as ``api_keys.github``.
    """

    name = "github_search"
    description = "GitHub code search for subdomain mentions"
    requires_api_key = True
    api_key_name = "github"

    def __init__(self, api_token: str) -> None:
        """Initialise with a GitHub API token.

        Args:
            api_token: GitHub personal access token.
        """
        super().__init__()
        self._token = api_token

    async def fetch(self, domain: str) -> Set[str]:
        """Search GitHub code for references to subdomains of *domain*.

        Args:
            domain: Root domain to enumerate.

        Returns:
            Set of discovered subdomain strings.
        """
        results: Set[str] = set()
        # Pattern to find subdomains in code/config files
        sub_pattern = re.compile(
            r'([\w\-]+(?:\.[\w\-]+)*\.' + re.escape(domain) + r')',
            re.IGNORECASE,
        )
        headers = {
            "Authorization": f"token {self._token}",
            "Accept": "application/vnd.github.v3+json",
        }
        query = f'"{domain}" in:file extension:txt OR extension:yaml OR extension:json OR extension:conf'
        url = f"https://api.github.com/search/code?q={query}&per_page=30"
        try:
            async with AsyncHTTPClient(timeout=30, retries=2, headers=headers) as client:
                resp = await client.get(url)
                if resp["status"] != 200:
                    return results
                data = json.loads(resp["body"])
                for item in data.get("items", []):
                    content_url = item.get("url", "")
                    if not content_url:
                        continue
                    content_resp = await client.get(content_url)
                    if content_resp["status"] != 200:
                        continue
                    content_data = json.loads(content_resp["body"])
                    import base64
                    raw_content = content_data.get("content", "")
                    try:
                        decoded = base64.b64decode(raw_content).decode("utf-8", errors="replace")
                    except Exception:  # noqa: BLE001
                        continue
                    for match in sub_pattern.finditer(decoded):
                        host = match.group(1).lower()
                        results.add(host)
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("GitHub search error: %s", exc)
        return results
