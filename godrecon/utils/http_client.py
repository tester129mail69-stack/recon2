"""Async HTTP client for GODRECON.

Provides :class:`AsyncHTTPClient` — a production-quality aiohttp wrapper with
connection pooling, automatic retry/backoff, User-Agent rotation, proxy
support, and rate limiting.
"""

from __future__ import annotations

import asyncio
import random
import time
from types import TracebackType
from typing import Any, Dict, List, Optional, Tuple, Type

import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector

from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_DEFAULT_USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]


class AsyncHTTPClient:
    """Async HTTP client with connection pooling, retries, and rotation.

    Usage::

        async with AsyncHTTPClient(timeout=10) as client:
            resp = await client.get("https://example.com")
            print(resp["status"], resp["body"][:200])
    """

    def __init__(
        self,
        timeout: int = 10,
        max_connections: int = 100,
        retries: int = 3,
        retry_delay: float = 1.0,
        user_agents: Optional[List[str]] = None,
        proxy: Optional[str] = None,
        verify_ssl: bool = True,
        rate_limit: float = 0.0,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Initialise the client (does *not* open a session yet).

        Args:
            timeout: Request timeout in seconds.
            max_connections: Maximum simultaneous TCP connections.
            retries: Number of retry attempts on transient failures.
            retry_delay: Base delay between retries (doubles each attempt).
            user_agents: Pool of User-Agent strings to rotate.
            proxy: Optional HTTP or SOCKS5 proxy URL.
            verify_ssl: Whether to verify TLS certificates.
            rate_limit: Minimum seconds between requests (0 = unlimited).
            headers: Additional default headers sent with every request.
        """
        self._timeout = timeout
        self._max_connections = max_connections
        self._retries = retries
        self._retry_delay = retry_delay
        self._user_agents = user_agents or _DEFAULT_USER_AGENTS
        self._proxy = proxy
        self._verify_ssl = verify_ssl
        self._rate_limit = rate_limit
        self._default_headers: Dict[str, str] = headers or {}
        self._session: Optional[ClientSession] = None
        self._last_request: float = 0.0
        self._cache: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "AsyncHTTPClient":
        await self._create_session()
        return self

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        await self.close()

    async def _create_session(self) -> None:
        """Create the underlying :class:`aiohttp.ClientSession`."""
        connector = TCPConnector(
            limit=self._max_connections,
            ssl=self._verify_ssl or None,
            ttl_dns_cache=300,
        )
        timeout = ClientTimeout(total=self._timeout)
        self._session = ClientSession(
            connector=connector,
            timeout=timeout,
            headers=self._default_headers,
        )

    async def close(self) -> None:
        """Close the underlying HTTP session and release connections."""
        if self._session and not self._session.closed:
            await self._session.close()

    # ------------------------------------------------------------------
    # Public HTTP methods
    # ------------------------------------------------------------------

    async def get(self, url: str, **kwargs: Any) -> Dict[str, Any]:
        """Perform an HTTP GET request.

        Args:
            url: Target URL.
            **kwargs: Extra arguments forwarded to :meth:`_request`.

        Returns:
            Response dict with ``status``, ``headers``, ``body``, ``url``.
        """
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> Dict[str, Any]:
        """Perform an HTTP POST request."""
        return await self._request("POST", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> Dict[str, Any]:
        """Perform an HTTP HEAD request."""
        return await self._request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs: Any) -> Dict[str, Any]:
        """Perform an HTTP OPTIONS request."""
        return await self._request("OPTIONS", url, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> Dict[str, Any]:
        """Perform an HTTP PUT request."""
        return await self._request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> Dict[str, Any]:
        """Perform an HTTP DELETE request."""
        return await self._request("DELETE", url, **kwargs)

    async def request(self, method: str, url: str, **kwargs: Any) -> Dict[str, Any]:
        """Perform an HTTP request with the given method.

        Args:
            method: HTTP method string (e.g. ``"GET"``, ``"POST"``).
            url: Target URL.
            **kwargs: Extra arguments forwarded to :meth:`_request`.

        Returns:
            Response dict with ``status``, ``headers``, ``body``, ``url``.
        """
        return await self._request(method.upper(), url, **kwargs)

    # ------------------------------------------------------------------
    # Bulk helpers
    # ------------------------------------------------------------------

    async def fetch_all(
        self,
        urls: List[str],
        concurrency: int = 50,
        method: str = "GET",
        **kwargs: Any,
    ) -> List[Dict[str, Any]]:
        """Fetch multiple URLs concurrently.

        Args:
            urls: List of URLs to fetch.
            concurrency: Maximum simultaneous requests.
            method: HTTP method string.
            **kwargs: Forwarded to each request.

        Returns:
            List of response dicts (same order as *urls*).
        """
        sem = asyncio.Semaphore(concurrency)

        async def _fetch_one(url: str) -> Dict[str, Any]:
            async with sem:
                return await self._request(method, url, **kwargs)

        tasks = [asyncio.create_task(_fetch_one(u)) for u in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [
            r if isinstance(r, dict) else {"url": u, "error": str(r), "status": -1}
            for u, r in zip(urls, results)
        ]

    # ------------------------------------------------------------------
    # Core request logic
    # ------------------------------------------------------------------

    async def _request(
        self,
        method: str,
        url: str,
        use_cache: bool = False,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Execute an HTTP request with retry/backoff logic.

        Args:
            method: HTTP method string.
            url: Target URL.
            use_cache: Return cached response if available.
            **kwargs: Forwarded to :meth:`aiohttp.ClientSession.request`.

        Returns:
            Response dict.

        Raises:
            aiohttp.ClientError: After all retries are exhausted.
        """
        if use_cache and url in self._cache:
            return self._cache[url]

        if self._session is None:
            await self._create_session()

        kwargs.setdefault("headers", {})
        kwargs["headers"]["User-Agent"] = random.choice(self._user_agents)

        if self._proxy:
            kwargs["proxy"] = self._proxy

        last_exc: Optional[Exception] = None
        for attempt in range(self._retries + 1):
            # Rate limiting
            if self._rate_limit > 0:
                now = time.monotonic()
                wait = self._rate_limit - (now - self._last_request)
                if wait > 0:
                    await asyncio.sleep(wait)
            self._last_request = time.monotonic()

            try:
                assert self._session is not None
                async with self._session.request(method, url, **kwargs) as resp:
                    body = ""
                    if method.upper() != "HEAD":
                        try:
                            body = await resp.text(errors="replace")
                        except Exception:  # noqa: BLE001
                            body = ""
                    response = {
                        "status": resp.status,
                        "headers": dict(resp.headers),
                        "body": body,
                        "url": str(resp.url),
                    }
                    if use_cache:
                        self._cache[url] = response
                    return response
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                last_exc = exc
                if attempt < self._retries:
                    backoff = self._retry_delay * (2 ** attempt)
                    logger.debug(
                        "Request to %s failed (attempt %d/%d): %s — retrying in %.1fs",
                        url,
                        attempt + 1,
                        self._retries + 1,
                        exc,
                        backoff,
                    )
                    await asyncio.sleep(backoff)

        raise last_exc or aiohttp.ClientError(f"Request failed: {url}")


