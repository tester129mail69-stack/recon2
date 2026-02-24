"""Async web spider for GODRECON."""

from __future__ import annotations

import asyncio
import re
from collections import deque
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_HREF_RE = re.compile(r'href=["\']([^"\'<>\s]+)["\']', re.IGNORECASE)
_SRC_RE = re.compile(r'src=["\']([^"\'<>\s]+)["\']', re.IGNORECASE)
_FORM_ACTION_RE = re.compile(r'<form[^>]*action=["\']([^"\'<>\s]+)["\']', re.IGNORECASE)
_COMMENT_RE = re.compile(r'<!--(.*?)-->', re.DOTALL)
_DISALLOW_RE = re.compile(r'Disallow:\s*(\S+)', re.IGNORECASE)


class WebSpider:
    """Async web crawler that follows links within the target domain."""

    def __init__(self, http: AsyncHTTPClient) -> None:
        """Initialise the spider.

        Args:
            http: Shared async HTTP client instance.
        """
        self._http = http

    async def crawl(
        self,
        start_url: str,
        max_depth: int = 3,
        max_pages: int = 100,
        respect_robots: bool = True,
    ) -> Dict[str, Any]:
        """Crawl the target website starting from *start_url*.

        Args:
            start_url: Entry-point URL to begin crawling.
            max_depth: Maximum link-follow depth.
            max_pages: Maximum number of pages to crawl.
            respect_robots: Whether to honour ``robots.txt`` Disallow rules.

        Returns:
            Dict with keys: pages, forms, scripts, links, comments.
        """
        parsed = urlparse(start_url)
        base_domain = parsed.netloc
        disallowed: Set[str] = set()

        if respect_robots:
            disallowed = await self._fetch_robots(
                f"{parsed.scheme}://{base_domain}/robots.txt"
            )

        pages: List[Dict[str, Any]] = []
        forms: List[Dict[str, Any]] = []
        scripts: List[str] = []
        external_links: List[str] = []
        comments: List[str] = []

        visited: Set[str] = set()
        queue: deque = deque([(start_url, 0)])

        while queue and len(pages) < max_pages:
            url, depth = queue.popleft()
            if url in visited or depth > max_depth:
                continue
            if self._is_disallowed(url, disallowed):
                logger.debug("robots.txt disallows %s", url)
                continue

            visited.add(url)
            page_data = await self._fetch_page(url)
            if not page_data:
                continue

            pages.append(page_data)
            body = page_data.get("body", "")

            # Collect forms
            page_forms = self._extract_forms(body, url)
            forms.extend(page_forms)

            # Extract comments
            for comment in _COMMENT_RE.findall(body):
                stripped = comment.strip()
                if stripped and len(stripped) > 3:
                    comments.append(stripped[:500])

            # Extract script src URLs
            for src in _SRC_RE.findall(body):
                abs_src = urljoin(url, src)
                if abs_src.endswith(".js") and abs_src not in scripts:
                    scripts.append(abs_src)

            # Queue internal links
            if depth < max_depth:
                for href in _HREF_RE.findall(body):
                    abs_url = urljoin(url, href)
                    parsed_link = urlparse(abs_url)
                    if parsed_link.netloc == base_domain:
                        clean = abs_url.split("#")[0]
                        if clean and clean not in visited:
                            queue.append((clean, depth + 1))
                    elif parsed_link.scheme in ("http", "https"):
                        if abs_url not in external_links:
                            external_links.append(abs_url)

        return {
            "pages": pages,
            "forms": forms,
            "scripts": list(dict.fromkeys(scripts)),
            "links": external_links[:200],
            "comments": list(dict.fromkeys(comments))[:100],
        }

    async def _fetch_page(self, url: str) -> Optional[Dict[str, Any]]:
        """Fetch a single page and return relevant data.

        Args:
            url: URL to fetch.

        Returns:
            Dict with url, status, body, content_type, or None on failure.
        """
        try:
            resp = await self._http.get(url, allow_redirects=True)
            if not resp:
                return None
            status = resp.get("status", 0)
            content_type = resp.get("headers", {}).get("content-type", "")
            if "text" not in content_type and "html" not in content_type:
                return None
            return {
                "url": resp.get("url", url),
                "status": status,
                "body": resp.get("body", ""),
                "content_type": content_type,
            }
        except Exception as exc:  # noqa: BLE001
            logger.debug("Spider fetch failed for %s: %s", url, exc)
            return None

    async def _fetch_robots(self, robots_url: str) -> Set[str]:
        """Fetch and parse robots.txt disallow rules.

        Args:
            robots_url: URL of the robots.txt file.

        Returns:
            Set of disallowed path prefixes.
        """
        disallowed: Set[str] = set()
        try:
            resp = await self._http.get(robots_url)
            if resp and resp.get("status") == 200:
                for match in _DISALLOW_RE.finditer(resp.get("body", "")):
                    path = match.group(1)
                    if path and path != "/":
                        disallowed.add(path)
        except Exception:  # noqa: BLE001
            pass
        return disallowed

    @staticmethod
    def _is_disallowed(url: str, disallowed: Set[str]) -> bool:
        """Check whether *url* matches any disallowed prefix.

        Args:
            url: URL to check.
            disallowed: Set of disallowed path prefixes.

        Returns:
            True if the URL should not be crawled.
        """
        path = urlparse(url).path
        return any(path.startswith(d) for d in disallowed)

    @staticmethod
    def _extract_forms(html: str, base_url: str) -> List[Dict[str, Any]]:
        """Extract form elements from *html*.

        Args:
            html: HTML content string.
            base_url: Base URL for resolving relative action URLs.

        Returns:
            List of form dicts with action, method, input list.
        """
        forms = []
        for form_match in re.finditer(r'<form([^>]*)>(.*?)</form>', html, re.DOTALL | re.IGNORECASE):
            attrs = form_match.group(1)
            body = form_match.group(2)

            action_m = re.search(r'action=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
            method_m = re.search(r'method=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
            action = urljoin(base_url, action_m.group(1)) if action_m else base_url
            method = method_m.group(1).strip().upper() if method_m else "GET"

            inputs = []
            for inp in re.finditer(r'<input([^>]*)>', body, re.IGNORECASE):
                inp_attrs = inp.group(1)
                name_m = re.search(r'name=["\']([^"\']*)["\']', inp_attrs, re.IGNORECASE)
                type_m = re.search(r'type=["\']([^"\']*)["\']', inp_attrs, re.IGNORECASE)
                value_m = re.search(r'value=["\']([^"\']*)["\']', inp_attrs, re.IGNORECASE)
                inputs.append({
                    "name": name_m.group(1) if name_m else "",
                    "type": type_m.group(1).lower() if type_m else "text",
                    "value": value_m.group(1) if value_m else "",
                })

            forms.append({
                "action": action,
                "method": method,
                "inputs": inputs,
                "page": base_url,
            })
        return forms
