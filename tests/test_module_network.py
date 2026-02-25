"""Tests for godrecon.modules.network.scanner."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from godrecon.core.config import Config
from godrecon.modules.base import ModuleResult
from godrecon.modules.network.scanner import NetworkIntelModule


def _make_cm_mock() -> MagicMock:
    mock = AsyncMock()
    mock.__aenter__ = AsyncMock(return_value=mock)
    mock.__aexit__ = AsyncMock(return_value=False)
    return mock


def test_instantiation():
    mod = NetworkIntelModule()
    assert mod is not None


def test_attributes():
    mod = NetworkIntelModule()
    assert mod.name == "network"
    assert mod.category == "network"
    assert mod.description


@pytest.mark.asyncio
async def test_execute_returns_module_result():
    http_mock = _make_cm_mock()
    dns_mock = _make_cm_mock()

    with (
        patch(
            "godrecon.modules.network.scanner.AsyncHTTPClient",
            return_value=http_mock,
        ),
        patch(
            "godrecon.modules.network.scanner.AsyncDNSResolver",
            return_value=dns_mock,
        ),
        patch.object(
            NetworkIntelModule,
            "_run_traceroute",
            new=AsyncMock(return_value={}),
        ),
        patch.object(
            NetworkIntelModule,
            "_run_cdn_bypass",
            new=AsyncMock(return_value={}),
        ),
        patch.object(
            NetworkIntelModule,
            "_run_geolocation",
            new=AsyncMock(return_value={}),
        ),
        patch.object(
            NetworkIntelModule,
            "_run_asn",
            new=AsyncMock(return_value={}),
        ),
        patch(
            "godrecon.modules.network.scanner.NetworkTopologyMapper",
            return_value=MagicMock(build_map=MagicMock(return_value={})),
        ),
    ):
        mod = NetworkIntelModule()
        result = await mod._execute("example.com", Config())

    assert isinstance(result, ModuleResult)
    assert result.module_name == "network"
    assert result.error is None


@pytest.mark.asyncio
async def test_execute_error_handling():
    with patch(
        "godrecon.modules.network.scanner.AsyncHTTPClient",
        side_effect=RuntimeError("network error"),
    ):
        mod = NetworkIntelModule()
        result = await mod.run("example.com", Config())

    assert result.error is not None
    assert result.findings == []
