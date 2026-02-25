"""Tests for godrecon.modules.api_intel.scanner."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from godrecon.core.config import Config
from godrecon.modules.base import ModuleResult
from godrecon.modules.api_intel.scanner import APIIntelModule


def _make_http_mock() -> MagicMock:
    mock = AsyncMock()
    mock.__aenter__ = AsyncMock(return_value=mock)
    mock.__aexit__ = AsyncMock(return_value=False)
    return mock


def test_instantiation():
    mod = APIIntelModule()
    assert mod is not None


def test_attributes():
    mod = APIIntelModule()
    assert mod.name == "api_intel"
    assert mod.category == "api"
    assert mod.description


@pytest.mark.asyncio
async def test_execute_returns_module_result():
    http_mock = _make_http_mock()
    discovery_mock = MagicMock()
    discovery_mock.discover = AsyncMock(return_value=[])

    with (
        patch(
            "godrecon.modules.api_intel.scanner.AsyncHTTPClient",
            return_value=http_mock,
        ),
        patch(
            "godrecon.modules.api_intel.scanner.APIDiscovery",
            return_value=discovery_mock,
        ),
    ):
        mod = APIIntelModule()
        result = await mod._execute("example.com", Config())

    assert isinstance(result, ModuleResult)
    assert result.module_name == "api_intel"
    assert result.error is None


@pytest.mark.asyncio
async def test_execute_error_handling():
    with patch(
        "godrecon.modules.api_intel.scanner.AsyncHTTPClient",
        side_effect=RuntimeError("api error"),
    ):
        mod = APIIntelModule()
        result = await mod.run("example.com", Config())

    assert result.error is not None
    assert result.findings == []
