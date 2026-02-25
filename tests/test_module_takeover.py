"""Tests for godrecon.modules.takeover.detector."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from godrecon.core.config import Config
from godrecon.modules.base import ModuleResult
from godrecon.modules.takeover.detector import TakeoverDetectorModule


def _make_cm_mock() -> MagicMock:
    mock = AsyncMock()
    mock.__aenter__ = AsyncMock(return_value=mock)
    mock.__aexit__ = AsyncMock(return_value=False)
    return mock


def test_instantiation():
    mod = TakeoverDetectorModule()
    assert mod is not None


def test_attributes():
    mod = TakeoverDetectorModule()
    assert mod.name == "takeover"
    assert mod.category == "takeover"
    assert mod.description


@pytest.mark.asyncio
async def test_execute_returns_module_result():
    dns_mock = _make_cm_mock()
    http_mock = _make_cm_mock()

    with (
        patch(
            "godrecon.modules.takeover.detector.AsyncDNSResolver",
            return_value=dns_mock,
        ),
        patch(
            "godrecon.modules.takeover.detector.AsyncHTTPClient",
            return_value=http_mock,
        ),
        patch.object(
            TakeoverDetectorModule,
            "_load_fingerprints",
            return_value=[{"service": "github", "cname": ["github.io"], "fingerprint": "404"}],
        ),
        patch.object(
            TakeoverDetectorModule,
            "_wait_for_subdomains",
            new=AsyncMock(return_value=["example.com"]),
        ),
        patch.object(
            TakeoverDetectorModule,
            "_check_subdomain",
            new=AsyncMock(return_value=None),
        ),
    ):
        mod = TakeoverDetectorModule()
        result = await mod._execute("example.com", Config())

    assert isinstance(result, ModuleResult)
    assert result.module_name == "takeover"
    assert result.error is None


@pytest.mark.asyncio
async def test_execute_disabled():
    cfg = Config()
    if hasattr(cfg, "takeover"):
        cfg.takeover.enabled = False  # type: ignore[attr-defined]

    with patch.object(
        TakeoverDetectorModule,
        "_load_fingerprints",
        return_value=[],
    ):
        mod = TakeoverDetectorModule()
        result = await mod._execute("example.com", cfg)

    assert isinstance(result, ModuleResult)
    assert result.error is None


@pytest.mark.asyncio
async def test_execute_error_handling():
    with (
        patch.object(
            TakeoverDetectorModule,
            "_load_fingerprints",
            return_value=[{"service": "test", "cname": ["test.io"], "fingerprint": "404"}],
        ),
        patch.object(
            TakeoverDetectorModule,
            "_wait_for_subdomains",
            new=AsyncMock(side_effect=RuntimeError("takeover error")),
        ),
    ):
        mod = TakeoverDetectorModule()
        result = await mod.run("example.com", Config())

    assert result.error is not None
    assert result.findings == []
