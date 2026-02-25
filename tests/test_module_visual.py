"""Tests for godrecon.modules.visual.scanner."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from godrecon.core.config import Config
from godrecon.modules.base import ModuleResult
from godrecon.modules.visual.scanner import VisualReconModule


def test_instantiation():
    mod = VisualReconModule()
    assert mod is not None


def test_attributes():
    mod = VisualReconModule()
    assert mod.name == "visual"
    assert mod.category == "visual"
    assert mod.description


@pytest.mark.asyncio
async def test_execute_screenshots_disabled():
    cfg = Config()
    cfg.visual.screenshots = False  # type: ignore[attr-defined]

    mod = VisualReconModule()

    with patch(
        "godrecon.modules.visual.scanner.ScreenshotCapture",
    ) as capture_cls:
        # screenshots disabled branch - capture should not be called
        result = await mod._execute("example.com", cfg)

    capture_cls.assert_not_called()
    assert isinstance(result, ModuleResult)
    assert result.module_name == "visual"
    assert result.error is None


@pytest.mark.asyncio
async def test_execute_returns_module_result():
    capturer_mock = MagicMock()
    capturer_mock.capture_all = AsyncMock(return_value=[])

    analyzer_mock = MagicMock()
    analyzer_mock.classify_page = MagicMock(return_value={})
    analyzer_mock.group_similar = MagicMock(return_value=[])

    with (
        patch(
            "godrecon.modules.visual.scanner.ScreenshotCapture",
            return_value=capturer_mock,
        ),
        patch(
            "godrecon.modules.visual.scanner.VisualSimilarityAnalyzer",
            return_value=analyzer_mock,
        ),
    ):
        mod = VisualReconModule()
        result = await mod._execute("example.com", Config())

    assert isinstance(result, ModuleResult)
    assert result.module_name == "visual"
    assert result.error is None


@pytest.mark.asyncio
async def test_execute_error_handling():
    with patch(
        "godrecon.modules.visual.scanner.ScreenshotCapture",
        side_effect=RuntimeError("screenshot error"),
    ):
        mod = VisualReconModule()
        result = await mod.run("example.com", Config())

    assert result.error is not None
    assert result.findings == []
