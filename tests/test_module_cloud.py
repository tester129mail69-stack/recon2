"""Tests for godrecon.modules.cloud.scanner."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from godrecon.core.config import Config
from godrecon.modules.base import ModuleResult
from godrecon.modules.cloud.scanner import CloudSecurityModule


def _make_http_mock() -> MagicMock:
    mock = AsyncMock()
    mock.__aenter__ = AsyncMock(return_value=mock)
    mock.__aexit__ = AsyncMock(return_value=False)
    return mock


def test_instantiation():
    mod = CloudSecurityModule()
    assert mod is not None


def test_attributes():
    mod = CloudSecurityModule()
    assert mod.name == "cloud"
    assert mod.category == "cloud"
    assert mod.description


@pytest.mark.asyncio
async def test_execute_returns_module_result():
    http_mock = _make_http_mock()
    empty_detect = AsyncMock(return_value=[])

    with (
        patch(
            "godrecon.modules.cloud.scanner.AsyncHTTPClient",
            return_value=http_mock,
        ),
        patch(
            "godrecon.modules.cloud.scanner.AWSDetector",
            return_value=MagicMock(detect=empty_detect),
        ),
        patch(
            "godrecon.modules.cloud.scanner.AzureDetector",
            return_value=MagicMock(detect=empty_detect),
        ),
        patch(
            "godrecon.modules.cloud.scanner.GCPDetector",
            return_value=MagicMock(detect=empty_detect),
        ),
    ):
        mod = CloudSecurityModule()
        result = await mod._execute("example.com", Config())

    assert isinstance(result, ModuleResult)
    assert result.module_name == "cloud"
    assert result.error is None


@pytest.mark.asyncio
async def test_execute_error_handling():
    with patch(
        "godrecon.modules.cloud.scanner.AsyncHTTPClient",
        side_effect=RuntimeError("cloud error"),
    ):
        mod = CloudSecurityModule()
        result = await mod.run("example.com", Config())

    assert result.error is not None
    assert result.findings == []
