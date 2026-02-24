"""Screenshot capture for GODRECON visual reconnaissance.

Captures full-page and viewport screenshots for live HTTP hosts.
Uses Playwright (async) when available; falls back to HTTP-based
metadata capture if Playwright is not installed.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Optional Playwright import
# ---------------------------------------------------------------------------
try:
    from playwright.async_api import async_playwright, Browser, BrowserContext, Page  # type: ignore[import]
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


class ScreenshotResult:
    """Result of a single screenshot capture attempt.

    Attributes:
        url: The final URL after any redirects.
        original_url: The URL that was requested.
        title: Page title (if captured).
        status_code: HTTP status code.
        screenshot_path: Path to saved PNG file, or ``None``.
        viewport_path: Path to saved viewport PNG, or ``None``.
        js_errors: JavaScript errors encountered on the page.
        console_output: Console messages from the page.
        error: Error message if the capture failed.
        metadata: Additional page metadata.
    """

    def __init__(self, original_url: str) -> None:
        self.original_url = original_url
        self.url: str = original_url
        self.title: Optional[str] = None
        self.status_code: Optional[int] = None
        self.screenshot_path: Optional[str] = None
        self.viewport_path: Optional[str] = None
        self.js_errors: List[str] = []
        self.console_output: List[str] = []
        self.error: Optional[str] = None
        self.metadata: Dict[str, Any] = {}

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain dictionary."""
        return {
            "original_url": self.original_url,
            "url": self.url,
            "title": self.title,
            "status_code": self.status_code,
            "screenshot_path": self.screenshot_path,
            "viewport_path": self.viewport_path,
            "js_errors": self.js_errors,
            "console_output": self.console_output,
            "error": self.error,
            "metadata": self.metadata,
        }


class ScreenshotCapture:
    """Headless browser screenshot capture using Playwright (or HTTP fallback).

    Args:
        output_dir: Directory to save screenshots.
        concurrency: Maximum simultaneous browser pages.
        timeout: Per-page timeout in seconds.
        viewport_width: Browser viewport width.
        viewport_height: Browser viewport height.
    """

    def __init__(
        self,
        output_dir: str = "output/screenshots",
        concurrency: int = 5,
        timeout: int = 15,
        viewport_width: int = 1280,
        viewport_height: int = 720,
    ) -> None:
        self.output_dir = Path(output_dir)
        self.concurrency = concurrency
        self.timeout = timeout
        self.viewport_width = viewport_width
        self.viewport_height = viewport_height

    async def capture_all(self, urls: List[str]) -> List[ScreenshotResult]:
        """Capture screenshots for all given *urls*.

        Args:
            urls: List of HTTP/HTTPS URLs to screenshot.

        Returns:
            List of :class:`ScreenshotResult` objects, one per URL.
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)

        if PLAYWRIGHT_AVAILABLE:
            return await self._capture_with_playwright(urls)
        else:
            logger.warning(
                "Playwright not installed — using HTTP metadata fallback. "
                "Install with: pip install playwright && playwright install chromium"
            )
            return await self._capture_with_http_fallback(urls)

    # ------------------------------------------------------------------
    # Playwright path
    # ------------------------------------------------------------------

    async def _capture_with_playwright(self, urls: List[str]) -> List[ScreenshotResult]:
        """Use Playwright for full browser screenshots.

        Args:
            urls: URLs to capture.

        Returns:
            List of :class:`ScreenshotResult` objects.
        """
        results: List[ScreenshotResult] = []
        semaphore = asyncio.Semaphore(self.concurrency)

        async with async_playwright() as pw:
            browser: Browser = await pw.chromium.launch(headless=True)
            try:
                tasks = [
                    self._capture_single_playwright(browser, url, semaphore)
                    for url in urls
                ]
                results = await asyncio.gather(*tasks, return_exceptions=False)
            finally:
                await browser.close()

        return list(results)

    async def _capture_single_playwright(
        self,
        browser: "Browser",
        url: str,
        semaphore: asyncio.Semaphore,
    ) -> ScreenshotResult:
        """Capture a single URL using Playwright.

        Args:
            browser: Playwright browser instance.
            url: Target URL.
            semaphore: Concurrency limiter.

        Returns:
            :class:`ScreenshotResult` for this URL.
        """
        result = ScreenshotResult(url)
        async with semaphore:
            context: "BrowserContext" = await browser.new_context(
                viewport={"width": self.viewport_width, "height": self.viewport_height},
                ignore_https_errors=True,
            )
            page: "Page" = await context.new_page()
            js_errors: List[str] = []
            console_msgs: List[str] = []

            page.on("pageerror", lambda exc: js_errors.append(str(exc)))
            page.on("console", lambda msg: console_msgs.append(f"{msg.type}: {msg.text}"))

            try:
                response = await page.goto(
                    url,
                    timeout=self.timeout * 1000,
                    wait_until="networkidle",
                )
                result.url = page.url
                result.title = await page.title()
                result.status_code = response.status if response else None
                result.js_errors = js_errors
                result.console_output = console_msgs

                # Safe filename from URL
                safe_name = _url_to_filename(url)

                # Full-page screenshot
                full_path = self.output_dir / f"{safe_name}_full.png"
                await page.screenshot(path=str(full_path), full_page=True)
                result.screenshot_path = str(full_path)

                # Viewport screenshot
                vp_path = self.output_dir / f"{safe_name}_viewport.png"
                await page.screenshot(path=str(vp_path), full_page=False)
                result.viewport_path = str(vp_path)

                logger.info("Screenshot captured: %s → %s", url, full_path)

            except Exception as exc:  # noqa: BLE001
                result.error = str(exc)
                logger.warning("Screenshot failed for %s: %s", url, exc)
            finally:
                await context.close()

        return result

    # ------------------------------------------------------------------
    # HTTP fallback path
    # ------------------------------------------------------------------

    async def _capture_with_http_fallback(self, urls: List[str]) -> List[ScreenshotResult]:
        """Use aiohttp to capture metadata when Playwright is unavailable.

        Args:
            urls: URLs to probe.

        Returns:
            List of :class:`ScreenshotResult` objects with metadata only.
        """
        import aiohttp

        semaphore = asyncio.Semaphore(self.concurrency)
        connector = aiohttp.TCPConnector(ssl=False, limit=self.concurrency)
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        results: List[ScreenshotResult] = []
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
        ) as session:
            tasks = [
                self._probe_url(session, url, semaphore) for url in urls
            ]
            results = await asyncio.gather(*tasks, return_exceptions=False)

        return list(results)

    @staticmethod
    async def _probe_url(
        session: Any,
        url: str,
        semaphore: asyncio.Semaphore,
    ) -> ScreenshotResult:
        """Probe a URL and capture metadata without a real browser.

        Args:
            session: aiohttp client session.
            url: Target URL.
            semaphore: Concurrency limiter.

        Returns:
            :class:`ScreenshotResult` with metadata only (no image).
        """
        result = ScreenshotResult(url)
        async with semaphore:
            try:
                async with session.get(
                    url,
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 GODRECON/1.0"},
                ) as resp:
                    result.url = str(resp.url)
                    result.status_code = resp.status
                    content_type = resp.headers.get("content-type", "")
                    body = await resp.text(errors="replace")
                    # Extract <title> from HTML
                    import re
                    m = re.search(r"<title[^>]*>([^<]*)</title>", body, re.IGNORECASE)
                    if m:
                        result.title = m.group(1).strip()
                    result.metadata = {
                        "content_type": content_type,
                        "content_length": resp.headers.get("content-length"),
                        "server": resp.headers.get("server"),
                        "playwright_available": False,
                    }
            except Exception as exc:  # noqa: BLE001
                result.error = str(exc)
        return result


def _url_to_filename(url: str) -> str:
    """Convert a URL to a filesystem-safe filename.

    Args:
        url: The URL to convert.

    Returns:
        A safe filename string (no extension).
    """
    parsed = urlparse(url)
    host = parsed.netloc.replace(":", "_")
    path = parsed.path.strip("/").replace("/", "_") or "root"
    return f"{host}_{path}"[:100]
