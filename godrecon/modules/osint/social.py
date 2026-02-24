"""Social media profile discovery for GODRECON OSINT."""

from __future__ import annotations

import asyncio
import re
from typing import Dict, List

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_PLATFORMS: List[Dict[str, str]] = [
    {"name": "GitHub", "url": "https://github.com/{username}", "indicator": "github.com"},
    {"name": "Twitter", "url": "https://twitter.com/{username}", "indicator": "twitter.com"},
    {"name": "LinkedIn", "url": "https://www.linkedin.com/company/{username}", "indicator": "linkedin.com"},
    {"name": "Facebook", "url": "https://www.facebook.com/{username}", "indicator": "facebook.com"},
    {"name": "Instagram", "url": "https://www.instagram.com/{username}/", "indicator": "instagram.com"},
    {"name": "YouTube", "url": "https://www.youtube.com/@{username}", "indicator": "youtube.com"},
    {"name": "Reddit", "url": "https://www.reddit.com/r/{username}/", "indicator": "reddit.com"},
]


def _generate_usernames(domain: str) -> List[str]:
    """Generate username candidates from a domain name.

    Args:
        domain: Target domain (e.g., ``example.com``).

    Returns:
        List of candidate usernames.
    """
    # Strip common TLDs and subdomains
    base = re.sub(r'\.(com|org|net|io|co|app|dev|ai|tech|info|biz|gov|edu)$', '', domain)
    base = re.sub(r'^www\.', '', base)
    base = base.split(".")[0]  # take only first label

    variants = [base]
    if "-" in base:
        variants.append(base.replace("-", ""))
        variants.append(base.replace("-", "_"))
    if "_" in base:
        variants.append(base.replace("_", ""))
        variants.append(base.replace("_", "-"))

    return list(dict.fromkeys(v.lower() for v in variants if v))


class SocialMediaScanner:
    """Discover social media profiles for target organisations."""

    def __init__(self, http: AsyncHTTPClient) -> None:
        """Initialise with an existing HTTP client.

        Args:
            http: Shared async HTTP client instance.
        """
        self._http = http

    async def scan(self, target: str) -> List[Dict]:
        """Check for social media profiles belonging to *target*.

        Args:
            target: Domain name of the target organisation.

        Returns:
            List of dicts with keys: platform, url, found, username.
        """
        usernames = _generate_usernames(target)
        tasks = []
        for username in usernames:
            for platform in _PLATFORMS:
                url = platform["url"].format(username=username)
                tasks.append(
                    asyncio.create_task(
                        self._check_profile(platform["name"], url, username)
                    )
                )

        results_raw = await asyncio.gather(*tasks, return_exceptions=True)
        findings: List[Dict] = []
        seen: set = set()
        for item in results_raw:
            if not isinstance(item, dict):
                continue
            key = (item["platform"], item["username"])
            if key in seen:
                continue
            seen.add(key)
            findings.append(item)

        return findings

    async def _check_profile(
        self, platform: str, url: str, username: str
    ) -> Dict:
        """Check whether a social media profile URL is live.

        Args:
            platform: Platform display name.
            url: Profile URL to probe.
            username: Username being checked.

        Returns:
            Dict with platform, url, found, username, status_code.
        """
        try:
            resp = await self._http.get(url, allow_redirects=True)
            status = resp.get("status", 0) if resp else 0
            found = status == 200
            return {
                "platform": platform,
                "url": url,
                "found": found,
                "username": username,
                "status_code": status,
            }
        except Exception as exc:  # noqa: BLE001
            logger.debug("Social check failed %s: %s", url, exc)
            return {
                "platform": platform,
                "url": url,
                "found": False,
                "username": username,
                "status_code": 0,
            }
