"""Tests for godrecon.core.rate_limiter."""

from __future__ import annotations

import time

import pytest

from godrecon.core.rate_limiter import AdaptiveRateLimiter, _parse_retry_after


def test_initial_rps():
    limiter = AdaptiveRateLimiter(initial_rps=10.0)
    assert limiter.current_rps == 10.0


def test_not_throttled_initially():
    limiter = AdaptiveRateLimiter()
    assert limiter.is_throttled is False


def test_backoff_on_429():
    limiter = AdaptiveRateLimiter(initial_rps=10.0, backoff_factor=0.5)
    limiter.record_response(429, {})
    assert limiter.current_rps == 5.0
    assert limiter.is_throttled is True


def test_backoff_on_503():
    limiter = AdaptiveRateLimiter(initial_rps=10.0, backoff_factor=0.5)
    limiter.record_response(503, {})
    assert limiter.current_rps == 5.0
    assert limiter.is_throttled is True


def test_backoff_never_below_min_rps():
    limiter = AdaptiveRateLimiter(initial_rps=1.0, min_rps=0.5, backoff_factor=0.1)
    for _ in range(20):
        limiter.record_response(429, {})
    assert limiter.current_rps >= 0.5


def test_recovery_on_200():
    limiter = AdaptiveRateLimiter(initial_rps=10.0, backoff_factor=0.5, recovery_factor=1.1)
    limiter.record_response(429, {})
    assert limiter.current_rps == 5.0
    limiter.record_response(200, {})
    assert limiter.current_rps == pytest.approx(5.5, rel=0.01)


def test_recovery_caps_at_initial_rps():
    limiter = AdaptiveRateLimiter(initial_rps=10.0, recovery_factor=2.0)
    limiter.record_response(429, {})  # rps = 5
    for _ in range(20):
        limiter.record_response(200, {})
    assert limiter.current_rps <= 10.0


def test_throttled_cleared_after_full_recovery():
    limiter = AdaptiveRateLimiter(initial_rps=10.0, backoff_factor=0.5, recovery_factor=2.0)
    limiter.record_response(429, {})
    assert limiter.is_throttled is True
    # Large recovery_factor means one 200 response brings us back to initial
    for _ in range(10):
        limiter.record_response(200, {})
    assert limiter.is_throttled is False


def test_retry_after_header_parsing():
    assert _parse_retry_after({"Retry-After": "30"}) == 30.0
    assert _parse_retry_after({"retry-after": "60"}) == 60.0
    assert _parse_retry_after({}) == 0.0
    assert _parse_retry_after({"Retry-After": "invalid-date"}) == 60.0


@pytest.mark.asyncio
async def test_acquire_respects_rate():
    """acquire() should space requests according to current_rps."""
    limiter = AdaptiveRateLimiter(initial_rps=50.0)
    start = time.monotonic()
    await limiter.acquire()
    await limiter.acquire()
    elapsed = time.monotonic() - start
    # At 50 rps the interval is 0.02 s; two acquires should take at least that
    assert elapsed >= 0.01  # generous lower bound


@pytest.mark.asyncio
async def test_acquire_honoured_retry_after():
    """If Retry-After sets a future timestamp, acquire() should wait."""
    limiter = AdaptiveRateLimiter(initial_rps=100.0)
    limiter.record_response(429, {"Retry-After": "0.05"})
    start = time.monotonic()
    await limiter.acquire()
    elapsed = time.monotonic() - start
    assert elapsed >= 0.04  # waited at least ~50 ms
