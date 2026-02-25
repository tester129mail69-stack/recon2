"""Tests for godrecon.modules.content_discovery.scanner."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from godrecon.core.config import Config
from godrecon.modules.base import ModuleResult
from godrecon.modules.content_discovery.scanner import ContentDiscoveryModule


def _make_http_mock() -> MagicMock:
    mock = AsyncMock()
    mock.__aenter__ = AsyncMock(return_value=mock)
    mock.__aexit__ = AsyncMock(return_value=False)
    return mock


def test_instantiation():
    mod = ContentDiscoveryModule()
    assert mod is not None


def test_attributes():
    mod = ContentDiscoveryModule()
    assert mod.name == "content_discovery"
    assert mod.category == "http"
    assert mod.description


@pytest.mark.asyncio
async def test_execute_returns_module_result():
    http_mock = _make_http_mock()
    disc_mock = MagicMock()
    disc_mock.run = AsyncMock(return_value=[])
    disc_mock.check_backups = AsyncMock(return_value=[])
    checker_mock = MagicMock()
    checker_mock.check = AsyncMock(return_value=[])

    with (
        patch(
            "godrecon.modules.content_discovery.scanner.AsyncHTTPClient",
            return_value=http_mock,
        ),
        patch(
            "godrecon.modules.content_discovery.scanner.ContentDiscovery",
            return_value=disc_mock,
        ),
        patch(
            "godrecon.modules.content_discovery.scanner.SensitiveFileChecker",
            return_value=checker_mock,
        ),
    ):
        mod = ContentDiscoveryModule()
        result = await mod._execute("example.com", Config())

    assert isinstance(result, ModuleResult)
    assert result.module_name == "content_discovery"
    assert result.error is None


@pytest.mark.asyncio
async def test_execute_error_handling():
    with patch(
        "godrecon.modules.content_discovery.scanner.AsyncHTTPClient",
        side_effect=RuntimeError("content error"),
    ):
        mod = ContentDiscoveryModule()
        result = await mod.run("example.com", Config())

    assert result.error is not None
    assert result.findings == []
