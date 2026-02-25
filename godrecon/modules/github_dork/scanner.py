"""GitHub code search dorking module for GODRECON."""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_DORK_QUERIES = [
    "password", "api_key", "secret", "token", "aws_access_key",
    "private_key", "database_url", "smtp", "ftp", "internal",
]

_GITHUB_SEARCH_URL = "https://api.github.com/search/code"
_RATE_LIMIT_SLEEP = 6.1  # ~10 req/min


class GitHubDorkModule(BaseModule):
    """GitHub code search for leaked secrets and sensitive data."""

    name = "github_dork"
    description = "GitHub code search for leaked secrets and sensitive data"
    category = "osint"
    version = "1.0.0"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        """Search GitHub for leaked secrets related to target domain."""
        result = ModuleResult(module_name=self.name, target=target)
        domain = target.lstrip("*.")

        token = getattr(getattr(config, "api_keys", None), "github", "") or ""
        if not token:
            logger.warning("No GitHub API token configured — skipping GitHub dorking module")
            result.raw = {"skipped": True, "reason": "no_github_token"}
            return result

        timeout = getattr(getattr(config, "general", None), "timeout", 10) or 10
        all_hits: List[Dict[str, Any]] = []

        for keyword in _DORK_QUERIES:
            hits = await self._search_github(domain, keyword, token, timeout)
            for hit in hits:
                hit["query"] = keyword
                all_hits.append(hit)
                result.findings.append(Finding(
                    title=f"GitHub Leaked Secret: {keyword} — {hit.get('repo_url', '')}",
                    description=(
                        f"Query: \"{domain}\" {keyword}\n"
                        f"Repository: {hit.get('repo_url', '')}\n"
                        f"File: {hit.get('file_path', '')}"
                    ),
                    severity="high",
                    data=hit,
                    tags=["github", "secret", "leak", keyword],
                ))

        result.raw = {"hits": all_hits, "total": len(all_hits)}
        logger.info("GitHub dork for %s: %d potential leaks found", target, len(all_hits))
        return result

    async def _search_github(
        self,
        domain: str,
        keyword: str,
        token: str,
        timeout: int = 10,
    ) -> List[Dict[str, Any]]:
        """Query GitHub code search API for a single keyword."""
        try:
            import aiohttp
        except ImportError:
            logger.warning("aiohttp not available")
            return []

        await asyncio.sleep(_RATE_LIMIT_SLEEP)

        params = {"q": f'"{domain}" {keyword}', "per_page": 10}
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "GODRECON",
        }

        try:
            async with aiohttp.ClientSession(headers=headers) as session:
                async with session.get(
                    _GITHUB_SEARCH_URL,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as resp:
                    if resp.status != 200:
                        logger.debug("GitHub search returned %d for %s/%s", resp.status, domain, keyword)
                        return []
                    data = await resp.json()
                    items = data.get("items", [])
                    results = []
                    for item in items:
                        repo = item.get("repository", {})
                        results.append({
                            "repo_url": repo.get("html_url", ""),
                            "file_path": item.get("path", ""),
                            "name": item.get("name", ""),
                            "query": keyword,
                        })
                    return results
        except Exception as exc:
            logger.debug("GitHub search error for %s/%s: %s", domain, keyword, exc)
            return []
