"""Tests for godrecon.modules.tech.scanner."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from godrecon.core.config import Config
from godrecon.modules.base import ModuleResult
from godrecon.modules.tech.scanner import TechDetectionModule


def _make_http_mock() -> MagicMock:
    mock = AsyncMock()
    mock.__aenter__ = AsyncMock(return_value=mock)
    mock.__aexit__ = AsyncMock(return_value=False)
    return mock


def test_instantiation():
    mod = TechDetectionModule()
    assert mod is not None


def test_attributes():
    mod = TechDetectionModule()
    assert mod.name == "tech"
    assert mod.category == "tech"
    assert mod.description


@pytest.mark.asyncio
async def test_execute_returns_module_result():
    http_mock = _make_http_mock()

    with (
        patch(
            "godrecon.modules.tech.scanner.AsyncHTTPClient",
            return_value=http_mock,
        ),
        patch.object(
            TechDetectionModule,
            "_fingerprint_url",
            new=AsyncMock(return_value=[]),
        ),
        patch(
            "godrecon.modules.tech.scanner.FaviconHasher",
            return_value=MagicMock(hash_favicon=AsyncMock(return_value={})),
        ),
    ):
        mod = TechDetectionModule()
        result = await mod._execute("example.com", Config())

    assert isinstance(result, ModuleResult)
    assert result.module_name == "tech"
    assert result.error is None


@pytest.mark.asyncio
async def test_execute_error_handling():
    with patch(
        "godrecon.modules.tech.scanner.AsyncHTTPClient",
        side_effect=RuntimeError("http error"),
    ):
        mod = TechDetectionModule()
        result = await mod.run("example.com", Config())

    assert result.error is not None
    assert result.findings == []
