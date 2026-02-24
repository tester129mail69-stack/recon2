"""HTTP/HTTPS probing logic for GODRECON.

Provides :class:`HTTPProber` which concurrently probes hosts/URLs for live
HTTP/HTTPS services and captures detailed response metadata.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import aiohttp

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# Common alternative ports to probe in addition to 80/443
EXTRA_PORTS = [8080, 8443, 8000, 8888, 3000, 5000, 9090, 4443]

_TITLE_RE = re.compile(r"<title[^>]*>([^<]{1,256})</title>", re.IGNORECASE | re.DOTALL)
_TITLE_SEARCH_LIMIT = 8192  # bytes of body to search for page title


class ProbeResult:
    """Container for a single HTTP probe result.

    Attributes:
        url: The probed URL (after redirects).
        original_url: The URL that was originally requested.
        status_code: HTTP status code (-1 on error).
        headers: Response headers dict.
        title: Extracted page title (empty string if none).
        content_length: Response body size in bytes.
        content_type: Value of the Content-Type header.
        redirect_chain: List of URLs in the redirect chain.
        response_time: Latency in seconds.
        server: Value of the Server header.
        http2: Whether the server negotiated HTTP/2.
        body_hash: MD5 hash of the response body for deduplication.
        body: Raw response body (may be truncated).
        error: Error message if the probe failed.
    """

    __slots__ = (
        "url",
        "original_url",
        "status_code",
        "headers",
        "title",
        "content_length",
        "content_type",
        "redirect_chain",
        "response_time",
        "server",
        "http2",
        "body_hash",
        "body",
        "error",
    )

    def __init__(
        self,
        original_url: str,
        url: str = "",
        status_code: int = -1,
        headers: Optional[Dict[str, str]] = None,
        title: str = "",
        content_length: int = 0,
        content_type: str = "",
        redirect_chain: Optional[List[str]] = None,
        response_time: float = 0.0,
        server: str = "",
        http2: bool = False,
        body_hash: str = "",
        body: str = "",
        error: Optional[str] = None,
    ) -> None:
        self.original_url = original_url
        self.url = url or original_url
        self.status_code = status_code
        self.headers = headers or {}
        self.title = title
        self.content_length = content_length
        self.content_type = content_type
        self.redirect_chain = redirect_chain or []
        self.response_time = response_time
        self.server = server
        self.http2 = http2
        self.body_hash = body_hash
        self.body = body
        self.error = error

    def is_live(self) -> bool:
        """Return True if the probe produced a valid HTTP response."""
        return self.status_code > 0

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain dict."""
        return {
            "url": self.url,
            "original_url": self.original_url,
            "status_code": self.status_code,
            "headers": self.headers,
            "title": self.title,
            "content_length": self.content_length,
            "content_type": self.content_type,
            "redirect_chain": self.redirect_chain,
            "response_time": self.response_time,
            "server": self.server,
            "http2": self.http2,
            "body_hash": self.body_hash,
            "error": self.error,
        }


class HTTPProber:
    """Concurrent HTTP/HTTPS prober.

    Uses :class:`~godrecon.utils.http_client.AsyncHTTPClient` to probe a list
    of hosts across standard and alternative ports and returns
    :class:`ProbeResult` objects for all live services.

    Args:
        http_client: Pre-configured :class:`AsyncHTTPClient` instance.
        ports: Additional ports to check beyond 80/443.
        concurrency: Maximum simultaneous requests.
        timeout: Per-request timeout in seconds.
        follow_redirects: Whether to follow HTTP redirects.
        max_redirects: Maximum redirect hops to follow.
    """

    def __init__(
        self,
        http_client: AsyncHTTPClient,
        ports: Optional[List[int]] = None,
        concurrency: int = 100,
        timeout: int = 10,
        follow_redirects: bool = True,
        max_redirects: int = 5,
    ) -> None:
        self._client = http_client
        self._ports = ports if ports is not None else [80, 443, 8080, 8443, 8000, 8888, 3000, 5000]
        self._concurrency = concurrency
        self._timeout = timeout
        self._follow_redirects = follow_redirects
        self._max_redirects = max_redirects

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def probe_target(self, target: str) -> List[ProbeResult]:
        """Probe all standard and alternative ports for *target*.

        Checks HTTP on port 80 and HTTPS on port 443 plus every port in
        :attr:`_ports`.  All checks run concurrently.

        Args:
            target: Domain name or IP address (no scheme).

        Returns:
            List of :class:`ProbeResult` objects for every responding service.
        """
        urls = self._build_urls(target)
        sem = asyncio.Semaphore(self._concurrency)

        async def _probe(url: str) -> ProbeResult:
            async with sem:
                return await self._probe_url(url)

        tasks = [asyncio.create_task(_probe(u)) for u in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        live: List[ProbeResult] = []
        for r in results:
            if isinstance(r, ProbeResult) and r.is_live():
                live.append(r)
            elif isinstance(r, Exception):
                logger.debug("Probe exception for %s: %s", target, r)
        return live

    async def probe_urls(self, urls: List[str]) -> List[ProbeResult]:
        """Probe an explicit list of URLs.

        Args:
            urls: Full URLs including scheme.

        Returns:
            List of :class:`ProbeResult` objects for responding services.
        """
        sem = asyncio.Semaphore(self._concurrency)

        async def _probe(url: str) -> ProbeResult:
            async with sem:
                return await self._probe_url(url)

        tasks = [asyncio.create_task(_probe(u)) for u in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        live: List[ProbeResult] = []
        for r in results:
            if isinstance(r, ProbeResult) and r.is_live():
                live.append(r)
        return live

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_urls(self, target: str) -> List[str]:
        """Build the full list of URLs to probe for *target*.

        Args:
            target: Bare hostname or IP.

        Returns:
            Deduplicated list of HTTP/HTTPS URLs.
        """
        urls = set()
        # Standard ports
        urls.add(f"http://{target}")
        urls.add(f"https://{target}")
        # Alternative ports
        for port in self._ports:
            if port == 80:
                urls.add(f"http://{target}")
            elif port == 443:
                urls.add(f"https://{target}")
            elif port in (8443, 4443):
                urls.add(f"https://{target}:{port}")
            else:
                urls.add(f"http://{target}:{port}")
        return list(urls)

    async def _probe_url(self, url: str) -> ProbeResult:
        """Perform a single HTTP probe.

        Args:
            url: Full URL to probe.

        Returns:
            :class:`ProbeResult` populated with response metadata.
        """
        redirect_chain: List[str] = []
        t0 = time.monotonic()
        try:
            # Use allow_redirects=True to follow redirects automatically, but
            # we also manually track the chain using aiohttp's history.
            resp_dict = await self._client.get(
                url,
                allow_redirects=self._follow_redirects,
                max_redirects=self._max_redirects,
            )
            elapsed = time.monotonic() - t0
            headers: Dict[str, str] = {
                k.lower(): v for k, v in resp_dict.get("headers", {}).items()
            }
            body: str = resp_dict.get("body", "")
            status: int = resp_dict.get("status", -1)
            final_url: str = resp_dict.get("url", url)

            # Reconstruct redirect chain from aiohttp history if available
            history = resp_dict.get("history", [])
            for h in history:
                if isinstance(h, str):
                    redirect_chain.append(h)
                elif isinstance(h, dict):
                    redirect_chain.append(h.get("url", ""))

            # Detect HTTP/2 via protocol field if aiohttp exposes it
            http2 = resp_dict.get("version", "") == "2"

            content_type = headers.get("content-type", "").split(";")[0].strip()
            server = headers.get("server", "")

            # Extract page title from HTML body
            title = ""
            if "text/html" in content_type:
                m = _TITLE_RE.search(body[:_TITLE_SEARCH_LIMIT])
                if m:
                    title = m.group(1).strip().replace("\n", " ").replace("\r", "")[:256]

            # Body hash for deduplication
            body_hash = hashlib.md5(body.encode("utf-8", errors="replace")).hexdigest()  # noqa: S324

            return ProbeResult(
                original_url=url,
                url=final_url,
                status_code=status,
                headers=headers,
                title=title,
                content_length=len(body),
                content_type=content_type,
                redirect_chain=redirect_chain,
                response_time=round(elapsed, 3),
                server=server,
                http2=http2,
                body_hash=body_hash,
                body=body[:65536],  # Store up to 64 KB
            )
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
            elapsed = time.monotonic() - t0
            logger.debug("Probe failed for %s: %s", url, exc)
            return ProbeResult(
                original_url=url,
                response_time=round(elapsed, 3),
                error=str(exc),
            )
        except Exception as exc:  # noqa: BLE001
            elapsed = time.monotonic() - t0
            logger.debug("Unexpected probe error for %s: %s", url, exc)
            return ProbeResult(
                original_url=url,
                response_time=round(elapsed, 3),
                error=str(exc),
            )
