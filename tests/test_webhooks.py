"""Tests for godrecon.integrations.webhooks."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from godrecon.integrations.webhooks import (
    DiscordIntegration,
    IntegrationManager,
    SIEMIntegration,
    SlackIntegration,
    WebhookIntegration,
)

# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------


def test_webhook_integration_init():
    w = WebhookIntegration(url="https://example.com/hook", retries=2)
    assert w.url == "https://example.com/hook"
    assert w.retries == 2
    assert w.method == "POST"
    assert w.name == "webhook"


def test_slack_integration_init():
    s = SlackIntegration(webhook_url="https://hooks.slack.com/test")
    assert s.webhook_url == "https://hooks.slack.com/test"
    assert s.name == "slack"


def test_discord_integration_init():
    d = DiscordIntegration(webhook_url="https://discord.com/api/webhooks/test")
    assert d.webhook_url == "https://discord.com/api/webhooks/test"
    assert d.name == "discord"


def test_siem_integration_init():
    siem = SIEMIntegration(endpoint="syslog://localhost:514", format="cef")
    assert siem.endpoint == "syslog://localhost:514"
    assert siem.format == "cef"
    assert siem.name == "siem"


# ---------------------------------------------------------------------------
# CEF format
# ---------------------------------------------------------------------------


def test_cef_format_generation():
    event = {"title": "SQL Injection", "description": "Blind SQLi found", "severity": "high", "target": "example.com"}
    cef = SIEMIntegration.to_cef(event)
    assert cef.startswith("CEF:0|GODRECON|GODRECON")
    assert "SQL Injection" in cef
    assert "dst=example.com" in cef
    assert "sev=high" in cef


def test_cef_severity_mapping():
    for sev, expected in [("critical", "10"), ("high", "8"), ("medium", "5"), ("low", "3"), ("info", "1")]:
        event = {"title": "T", "description": "D", "severity": sev, "target": "t"}
        cef = SIEMIntegration.to_cef(event)
        assert f"|{expected}|" in cef


def test_cef_escapes_pipe_in_name():
    event = {"title": "Finding|Test", "description": "", "severity": "info", "target": "t"}
    cef = SIEMIntegration.to_cef(event)
    assert "Finding\\|Test" in cef


# ---------------------------------------------------------------------------
# HTTP sends — mocked aiohttp
# ---------------------------------------------------------------------------


def _mock_aiohttp_session(status: int = 200) -> MagicMock:
    mock_resp = AsyncMock()
    mock_resp.status = status
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=False)

    mock_session = MagicMock()
    mock_session.post = MagicMock(return_value=mock_resp)
    mock_session.request = MagicMock(return_value=mock_resp)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)
    return mock_session


@pytest.mark.asyncio
async def test_webhook_send_success():
    event = {"title": "Test", "severity": "low"}
    mock_session = _mock_aiohttp_session(status=200)
    with patch("aiohttp.ClientSession", return_value=mock_session):
        w = WebhookIntegration(url="https://example.com/hook")
        result = await w.send(event)
    assert result is True


@pytest.mark.asyncio
async def test_webhook_send_failure_status():
    event = {"title": "Test", "severity": "low"}
    mock_session = _mock_aiohttp_session(status=500)
    with patch("aiohttp.ClientSession", return_value=mock_session):
        w = WebhookIntegration(url="https://example.com/hook", retries=1)
        result = await w.send(event)
    assert result is False


@pytest.mark.asyncio
async def test_slack_send_success():
    event = {"title": "Alert", "description": "desc", "severity": "critical", "target": "example.com"}
    mock_session = _mock_aiohttp_session(status=200)
    with patch("aiohttp.ClientSession", return_value=mock_session):
        s = SlackIntegration(webhook_url="https://hooks.slack.com/test")
        result = await s.send(event)
    assert result is True


@pytest.mark.asyncio
async def test_discord_send_success():
    event = {"title": "Alert", "description": "desc", "severity": "high", "target": "example.com"}
    mock_session = _mock_aiohttp_session(status=204)
    with patch("aiohttp.ClientSession", return_value=mock_session):
        d = DiscordIntegration(webhook_url="https://discord.com/api/webhooks/test")
        result = await d.send(event)
    assert result is True


# ---------------------------------------------------------------------------
# IntegrationManager
# ---------------------------------------------------------------------------


def test_manager_register():
    manager = IntegrationManager()
    manager.register(SlackIntegration("https://hooks.slack.com/x"))
    manager.register(WebhookIntegration("https://example.com/hook"))
    assert len(manager._integrations) == 2


@pytest.mark.asyncio
async def test_manager_notify_all():
    manager = IntegrationManager()
    mock_integ = MagicMock()
    mock_integ.name = "mock"
    mock_integ.send = AsyncMock(return_value=True)
    manager.register(mock_integ)

    event = {"title": "Test", "severity": "info"}
    results = await manager.notify_all(event)
    assert results == {"mock": True}
    mock_integ.send.assert_called_once_with(event)


@pytest.mark.asyncio
async def test_manager_notify_all_multiple():
    manager = IntegrationManager()

    for name in ("a", "b", "c"):
        m = MagicMock()
        m.name = name
        m.send = AsyncMock(return_value=True)
        manager.register(m)

    results = await manager.notify_all({"event": "scan_done"})
    assert set(results.keys()) == {"a", "b", "c"}
    assert all(results.values())


def test_manager_from_config():
    from godrecon.core.config import Config

    cfg = Config()
    cfg.notifications.slack.enabled = True
    cfg.notifications.slack.webhook_url = "https://hooks.slack.com/x"
    manager = IntegrationManager.from_config(cfg)
    names = [i.name for i in manager._integrations]
    assert "slack" in names
