"""Tests for godrecon.modules.dns.dns_intel."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from godrecon.core.config import Config
from godrecon.modules.base import ModuleResult
from godrecon.modules.dns.dns_intel import DNSIntelModule


def _make_cm_mock() -> MagicMock:
    mock = AsyncMock()
    mock.__aenter__ = AsyncMock(return_value=mock)
    mock.__aexit__ = AsyncMock(return_value=False)
    return mock


def test_instantiation():
    mod = DNSIntelModule()
    assert mod is not None


def test_attributes():
    mod = DNSIntelModule()
    assert mod.name == "dns"
    assert mod.category == "dns"
    assert mod.description


@pytest.mark.asyncio
async def test_execute_returns_module_result():
    dns_mock = _make_cm_mock()
    http_mock = _make_cm_mock()

    empty = AsyncMock(return_value={})

    with (
        patch(
            "godrecon.modules.dns.dns_intel.AsyncDNSResolver",
            return_value=dns_mock,
        ),
        patch(
            "godrecon.modules.dns.dns_intel.AsyncHTTPClient",
            return_value=http_mock,
        ),
        patch(
            "godrecon.modules.dns.dns_intel.DNSRecordResolver",
            return_value=MagicMock(resolve_all=empty),
        ),
        patch(
            "godrecon.modules.dns.dns_intel.DNSSECValidator",
            return_value=MagicMock(validate=empty),
        ),
        patch(
            "godrecon.modules.dns.dns_intel.ZoneTransferChecker",
            return_value=MagicMock(check=empty),
        ),
        patch(
            "godrecon.modules.dns.dns_intel.DNSSecurityAnalyzer",
            return_value=MagicMock(analyze=empty),
        ),
        patch(
            "godrecon.modules.dns.dns_intel.EmailSecurityAnalyzer",
            return_value=MagicMock(analyze=empty),
        ),
        patch(
            "godrecon.modules.dns.dns_intel.DNSHistoryChecker",
            return_value=MagicMock(check=empty),
        ),
    ):
        mod = DNSIntelModule()
        result = await mod._execute("example.com", Config())

    assert isinstance(result, ModuleResult)
    assert result.module_name == "dns"
    assert result.target == "example.com"
    assert result.error is None


@pytest.mark.asyncio
async def test_execute_error_handling():
    with patch(
        "godrecon.modules.dns.dns_intel.AsyncDNSResolver",
        side_effect=RuntimeError("network error"),
    ):
        mod = DNSIntelModule()
        result = await mod.run("example.com", Config())

    assert result.error is not None
    assert result.findings == []
