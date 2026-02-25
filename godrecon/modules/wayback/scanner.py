"""Wayback Machine URL history discovery module for GODRECON."""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_CDX_URL = "http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original,timestamp,statuscode,mimetype&collapse=urlkey&limit=1000"

# URL category patterns
_INTERESTING_PATHS = ["/admin", "/api/", "/config", "/backup", ".env", ".git", ".bak", "/.htaccess", "/wp-admin", "/phpmyadmin", "password", "secret", "token", "private"]
_CATEGORIES = {
    "api_endpoints": ["/api/", "/v1/", "/v2/", "/graphql", "/rest/", "/json"],
    "admin_panels": ["/admin", "/administrator", "/wp-admin", "/phpmyadmin", "/cpanel"],
    "config_files": [".env", ".config", ".yml", ".yaml", ".xml", ".json", ".ini", ".cfg"],
    "backup_files": [".bak", ".backup", ".old", ".orig", ".copy", "~", ".swp"],
    "documents": [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv"],
    "scripts": [".js", ".ts", ".php", ".py", ".rb", ".sh"],
}


class WaybackModule(BaseModule):
    """Wayback Machine URL history discovery."""

    name = "wayback"
    description = "Wayback Machine URL history discovery"
    category = "osint"
    version = "1.0.0"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=target)
        domain = target.lstrip("*.")

        try:
            import aiohttp
        except ImportError:
            logger.warning("aiohttp not available — skipping Wayback module")
            result.error = "aiohttp not installed"
            return result

        urls = await self._fetch_cdx(domain, config.general.timeout)
        if not urls:
            result.raw = {"urls_found": 0, "categories": {}}
            return result

        categorized = self._categorize_urls(urls)
        interesting = self._find_interesting(urls)
        unique_urls = list(set(urls))[:500]  # limit to 500

        result.raw = {
            "urls_found": len(unique_urls),
            "categories": {k: list(v)[:50] for k, v in categorized.items()},
            "interesting": interesting[:50],
        }

        if interesting:
            result.findings.append(Finding(
                title=f"Wayback: {len(interesting)} interesting historical URLs found",
                description="Interesting historical URLs: " + ", ".join(interesting[:10]),
                severity="medium",
                data={"interesting": interesting[:50], "total_urls": len(unique_urls)},
                tags=["wayback", "osint", "historical"],
            ))
        elif unique_urls:
            result.findings.append(Finding(
                title=f"Wayback: {len(unique_urls)} historical URLs discovered",
                description=f"Found {len(unique_urls)} unique URLs in Wayback Machine",
                severity="info",
                data={"total_urls": len(unique_urls)},
                tags=["wayback", "osint"],
            ))

        logger.info("Wayback scan for %s: %d URLs, %d interesting", target, len(unique_urls), len(interesting))
        return result

    async def _fetch_cdx(self, domain: str, timeout: int = 10) -> List[str]:
        """Fetch URLs from Wayback CDX API."""
        import aiohttp
        url = _CDX_URL.format(domain=domain)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout * 3)) as resp:
                    if resp.status != 200:
                        return []
                    data = await resp.json(content_type=None)
                    if not data or len(data) < 2:
                        return []
                    # First row is header
                    return [row[0] for row in data[1:] if row and len(row) > 0]
        except Exception as exc:
            logger.debug("Wayback CDX fetch failed: %s", exc)
            return []

    @staticmethod
    def _categorize_urls(urls: List[str]) -> Dict[str, List[str]]:
        """Categorize URLs by type."""
        categories: Dict[str, List[str]] = {k: [] for k in _CATEGORIES}
        for url in urls:
            url_lower = url.lower()
            for cat, patterns in _CATEGORIES.items():
                if any(p in url_lower for p in patterns):
                    if url not in categories[cat]:
                        categories[cat].append(url)
        return categories

    @staticmethod
    def _find_interesting(urls: List[str]) -> List[str]:
        """Find interesting/sensitive URLs."""
        interesting = []
        for url in urls:
            url_lower = url.lower()
            if any(p in url_lower for p in _INTERESTING_PATHS):
                interesting.append(url)
        return interesting
