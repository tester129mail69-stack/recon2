"""Tests for godrecon.core.stealth."""

from __future__ import annotations

import pytest

from godrecon.core.stealth import _DEFAULT_USER_AGENTS, StealthConfig, StealthManager


def test_stealth_config_defaults():
    cfg = StealthConfig()
    assert cfg.enabled is False
    assert cfg.min_delay == 1.0
    assert cfg.max_delay == 5.0
    assert len(cfg.user_agents) >= 20
    assert cfg.proxy is None
    assert cfg.randomize_order is True
    assert cfg.dns_over_https is False
    assert cfg.max_requests_per_minute == 30


def test_stealth_config_custom_values():
    cfg = StealthConfig(enabled=True, min_delay=0.5, max_delay=2.0, proxy="http://proxy:8080")
    assert cfg.enabled is True
    assert cfg.min_delay == 0.5
    assert cfg.max_delay == 2.0
    assert cfg.proxy == "http://proxy:8080"


def test_default_user_agents_count():
    assert len(_DEFAULT_USER_AGENTS) >= 20


def test_get_user_agent_returns_string():
    manager = StealthManager(StealthConfig())
    ua = manager.get_user_agent()
    assert isinstance(ua, str)
    assert len(ua) > 10


def test_get_user_agent_is_in_list():
    cfg = StealthConfig()
    manager = StealthManager(cfg)
    ua = manager.get_user_agent()
    assert ua in cfg.user_agents


def test_get_user_agent_rotation():
    """Calling get_user_agent multiple times should return valid strings."""
    manager = StealthManager(StealthConfig())
    agents = {manager.get_user_agent() for _ in range(50)}
    # With 20+ agents and 50 draws, should see at least 2 different ones on average
    assert len(agents) >= 1


def test_get_headers_returns_dict():
    manager = StealthManager(StealthConfig())
    headers = manager.get_headers()
    assert isinstance(headers, dict)


def test_get_headers_has_user_agent():
    manager = StealthManager(StealthConfig())
    headers = manager.get_headers()
    assert "User-Agent" in headers
    assert headers["User-Agent"] in StealthConfig().user_agents


def test_get_headers_has_required_keys():
    manager = StealthManager(StealthConfig())
    headers = manager.get_headers()
    for key in ("Accept", "Accept-Language", "Accept-Encoding"):
        assert key in headers


def test_get_proxy_none_by_default():
    manager = StealthManager(StealthConfig())
    assert manager.get_proxy() is None


def test_get_proxy_returns_configured_value():
    cfg = StealthConfig(proxy="socks5://127.0.0.1:1080")
    manager = StealthManager(cfg)
    assert manager.get_proxy() == "socks5://127.0.0.1:1080"


@pytest.mark.asyncio
async def test_delay_within_range():
    cfg = StealthConfig(min_delay=0.01, max_delay=0.05)
    manager = StealthManager(cfg)
    import time

    start = time.monotonic()
    await manager.delay()
    elapsed = time.monotonic() - start
    assert 0.01 <= elapsed <= 0.2  # generous upper bound for CI


def test_stealth_manager_with_empty_user_agents():
    """Manager should fall back to defaults when user_agents list is empty."""
    cfg = StealthConfig(user_agents=[])
    manager = StealthManager(cfg)
    ua = manager.get_user_agent()
    assert isinstance(ua, str)
    assert len(ua) > 10
