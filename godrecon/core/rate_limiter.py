"""Adaptive rate limiter — detects and respects target rate limits."""

from __future__ import annotations

import asyncio
import time


class AdaptiveRateLimiter:
    """Token-bucket style rate limiter that adapts to 429/503 responses.

    On a 429 or 503 response the rate is multiplied by *backoff_factor* (< 1).
    On every successful 200 response the rate is gradually increased by
    *recovery_factor* (> 1), up to *initial_rps*.

    Args:
        initial_rps: Starting (and maximum) requests per second.
        min_rps: Minimum requests per second — the rate never falls below this.
        backoff_factor: Multiplicative factor applied when rate limiting is detected.
        recovery_factor: Multiplicative factor applied on successful responses.
    """

    def __init__(
        self,
        initial_rps: float = 10.0,
        min_rps: float = 0.5,
        backoff_factor: float = 0.5,
        recovery_factor: float = 1.1,
    ) -> None:
        self._initial_rps = initial_rps
        self._min_rps = min_rps
        self._backoff_factor = backoff_factor
        self._recovery_factor = recovery_factor
        self._rps = initial_rps
        self._throttled = False
        self._retry_after: float = 0.0  # absolute timestamp when we can send again
        self._lock = asyncio.Lock()
        self._last_request: float = 0.0

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def current_rps(self) -> float:
        """Current requests-per-second rate."""
        return self._rps

    @property
    def is_throttled(self) -> bool:
        """``True`` if we are currently in a backoff period."""
        return self._throttled

    # ------------------------------------------------------------------
    # Token acquisition
    # ------------------------------------------------------------------

    async def acquire(self) -> None:
        """Wait until a request slot is available."""
        async with self._lock:
            now = time.monotonic()

            # Honour Retry-After if set
            if self._retry_after > now:
                await asyncio.sleep(self._retry_after - now)
                now = time.monotonic()

            # Enforce the current rate limit
            min_interval = 1.0 / self._rps if self._rps > 0 else 1.0
            elapsed = now - self._last_request
            if elapsed < min_interval:
                await asyncio.sleep(min_interval - elapsed)

            self._last_request = time.monotonic()

    # ------------------------------------------------------------------
    # Feedback loop
    # ------------------------------------------------------------------

    def record_response(self, status_code: int, headers: dict) -> None:
        """Update internal rate based on the HTTP response.

        Args:
            status_code: HTTP status code of the response.
            headers: Response headers dict (used to parse ``Retry-After``).
        """
        if status_code == 429:
            self._rps = max(self._rps * self._backoff_factor, self._min_rps)
            self._throttled = True
            retry_after = _parse_retry_after(headers)
            if retry_after > 0:
                self._retry_after = time.monotonic() + retry_after
        elif status_code == 503:
            self._rps = max(self._rps * self._backoff_factor, self._min_rps)
            self._throttled = True
        elif status_code == 200:
            new_rps = min(self._rps * self._recovery_factor, self._initial_rps)
            self._rps = new_rps
            if self._rps >= self._initial_rps * 0.99:
                self._throttled = False


def _parse_retry_after(headers: dict) -> float:
    """Parse the ``Retry-After`` header value into seconds.

    Args:
        headers: Response headers dict.

    Returns:
        Number of seconds to wait, or 0 if the header is absent / unparseable.
    """
    value = headers.get("Retry-After") or headers.get("retry-after") or ""
    if not value:
        return 0.0
    try:
        return float(value)
    except ValueError:
        pass
    # RFC 7231 HTTP-date format — return a generous 60 s default
    return 60.0
