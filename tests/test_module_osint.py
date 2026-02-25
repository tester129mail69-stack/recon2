"""Tests for godrecon.modules.osint.scanner."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from godrecon.core.config import Config
from godrecon.modules.base import ModuleResult
from godrecon.modules.osint.scanner import OSINTModule


def _make_http_mock() -> MagicMock:
    mock = AsyncMock()
    mock.__aenter__ = AsyncMock(return_value=mock)
    mock.__aexit__ = AsyncMock(return_value=False)
    return mock


def test_instantiation():
    mod = OSINTModule()
    assert mod is not None


def test_attributes():
    mod = OSINTModule()
    assert mod.name == "osint"
    assert mod.category == "osint"
    assert mod.description


@pytest.mark.asyncio
async def test_execute_returns_module_result():
    http_mock = _make_http_mock()

    whois_result = {"registrar": "Test Registrar", "creation_date": "2000-01-01"}
    social_result: list = []
    dork_result: list = []

    with (
        patch(
            "godrecon.modules.osint.scanner.AsyncHTTPClient",
            return_value=http_mock,
        ),
        patch(
            "godrecon.modules.osint.scanner.WHOISLookup",
            return_value=MagicMock(lookup=AsyncMock(return_value=whois_result)),
        ),
        patch(
            "godrecon.modules.osint.scanner.SocialMediaScanner",
            return_value=MagicMock(scan=AsyncMock(return_value=social_result)),
        ),
        patch(
            "godrecon.modules.osint.scanner.GoogleDorkScanner",
            return_value=MagicMock(generate_dorks=AsyncMock(return_value=dork_result)),
        ),
    ):
        mod = OSINTModule()
        result = await mod._execute("example.com", Config())

    assert isinstance(result, ModuleResult)
    assert result.module_name == "osint"
    assert result.error is None


@pytest.mark.asyncio
async def test_execute_error_handling():
    with patch(
        "godrecon.modules.osint.scanner.AsyncHTTPClient",
        side_effect=RuntimeError("osint error"),
    ):
        mod = OSINTModule()
        result = await mod.run("example.com", Config())

    assert result.error is not None
    assert result.findings == []
