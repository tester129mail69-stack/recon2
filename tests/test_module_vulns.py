"""Tests for godrecon.modules.vulns.scanner."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from godrecon.core.config import Config
from godrecon.modules.base import ModuleResult
from godrecon.modules.vulns.scanner import VulnerabilityModule


def _make_http_mock() -> MagicMock:
    mock = AsyncMock()
    mock.__aenter__ = AsyncMock(return_value=mock)
    mock.__aexit__ = AsyncMock(return_value=False)
    return mock


def test_instantiation():
    mod = VulnerabilityModule()
    assert mod is not None


def test_attributes():
    mod = VulnerabilityModule()
    assert mod.name == "vulns"
    assert mod.category == "vulns"
    assert mod.description


@pytest.mark.asyncio
async def test_execute_returns_module_result():
    http_mock = _make_http_mock()

    with (
        patch(
            "godrecon.modules.vulns.scanner.AsyncHTTPClient",
            return_value=http_mock,
        ),
        patch.object(
            VulnerabilityModule,
            "_wait_for_subdomains",
            new=AsyncMock(return_value=["example.com"]),
        ),
        patch.object(
            VulnerabilityModule,
            "_scan_target",
            new=AsyncMock(return_value=([], [])),
        ),
        patch(
            "godrecon.modules.vulns.scanner.get_notifier_from_config",
            return_value=None,
        ),
    ):
        mod = VulnerabilityModule()
        result = await mod._execute("example.com", Config())

    assert isinstance(result, ModuleResult)
    assert result.module_name == "vulns"
    assert result.error is None


@pytest.mark.asyncio
async def test_execute_error_handling():
    with (
        patch.object(
            VulnerabilityModule,
            "_wait_for_subdomains",
            new=AsyncMock(side_effect=RuntimeError("boom")),
        ),
        patch(
            "godrecon.modules.vulns.scanner.get_notifier_from_config",
            return_value=None,
        ),
    ):
        mod = VulnerabilityModule()
        result = await mod.run("example.com", Config())

    assert result.error is not None
    assert result.findings == []
