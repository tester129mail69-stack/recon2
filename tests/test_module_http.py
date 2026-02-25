"""Tests for godrecon.modules.http.probe."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from godrecon.core.config import Config
from godrecon.modules.base import ModuleResult
from godrecon.modules.http.probe import HTTPProbeModule


def _make_http_mock() -> MagicMock:
    mock = AsyncMock()
    mock.__aenter__ = AsyncMock(return_value=mock)
    mock.__aexit__ = AsyncMock(return_value=False)
    return mock


def test_instantiation():
    mod = HTTPProbeModule()
    assert mod is not None


def test_attributes():
    mod = HTTPProbeModule()
    assert mod.name == "http"
    assert mod.category == "http"
    assert mod.description


@pytest.mark.asyncio
async def test_execute_no_live_hosts():
    http_mock = _make_http_mock()
    prober_mock = MagicMock()
    prober_mock.probe_target = AsyncMock(return_value=[])

    with (
        patch(
            "godrecon.modules.http.probe.AsyncHTTPClient",
            return_value=http_mock,
        ),
        patch(
            "godrecon.modules.http.probe.HTTPProber",
            return_value=prober_mock,
        ),
    ):
        mod = HTTPProbeModule()
        result = await mod._execute("example.com", Config())

    assert isinstance(result, ModuleResult)
    assert result.module_name == "http"
    assert result.error is None
    assert any("No HTTP Services" in f.title for f in result.findings)


@pytest.mark.asyncio
async def test_execute_error_handling():
    with patch(
        "godrecon.modules.http.probe.AsyncHTTPClient",
        side_effect=RuntimeError("connection failed"),
    ):
        mod = HTTPProbeModule()
        result = await mod.run("example.com", Config())

    assert result.error is not None
    assert result.findings == []
