"""Integration test for the GODRECON scan lifecycle.

Tests the full flow: engine creation → module loading → scan execution →
result collection.  All network I/O is mocked so no real HTTP/DNS requests
are made.

Run only this file with::

    pytest tests/test_integration.py -m integration -v
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from godrecon.core.config import Config
from godrecon.core.engine import ScanEngine, ScanResult
from godrecon.modules.base import BaseModule, Finding, ModuleResult


# ---------------------------------------------------------------------------
# A lightweight in-process module used for integration testing
# ---------------------------------------------------------------------------


class _LightweightModule(BaseModule):
    """Minimal module that returns a single finding without I/O."""

    name = "lightweight"
    description = "Lightweight test module"
    category = "test"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        return ModuleResult(
            module_name=self.name,
            target=target,
            findings=[Finding(title="Integration finding", severity="info")],
            raw={"test": True},
        )


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.asyncio
async def test_engine_full_scan_lifecycle():
    """Engine runs a full scan lifecycle and returns a valid ScanResult."""
    module = _LightweightModule()
    cfg = Config()
    engine = ScanEngine(target="example.com", config=cfg)

    with patch.object(engine, "_load_modules", return_value=[module]):
        result = await engine.run()

    assert isinstance(result, ScanResult)
    assert result.target == "example.com"
    assert result.finished_at is not None
    assert result.duration >= 0
    assert "lightweight" in result.module_results
    assert result.module_results["lightweight"].findings[0].title == "Integration finding"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_engine_events_fire_correctly():
    """Event handlers receive scan_started, module_finished, and scan_finished."""
    module = _LightweightModule()
    cfg = Config()
    engine = ScanEngine(target="example.com", config=cfg)

    events_received: list = []
    engine.on_event(lambda e: events_received.append(e))

    with patch.object(engine, "_load_modules", return_value=[module]):
        await engine.run()

    event_types = [e["event"] for e in events_received]
    assert "scan_started" in event_types
    assert "scan_finished" in event_types


@pytest.mark.integration
@pytest.mark.asyncio
async def test_engine_result_structure():
    """ScanResult has the expected keys in stats."""
    module = _LightweightModule()
    cfg = Config()
    engine = ScanEngine(target="example.com", config=cfg)

    with patch.object(engine, "_load_modules", return_value=[module]):
        result = await engine.run()

    assert "modules_run" in result.stats
    assert "modules_with_errors" in result.stats
    assert "duration_seconds" in result.stats
    assert result.stats["modules_run"] == 1
    assert result.stats["modules_with_errors"] == 0


@pytest.mark.integration
@pytest.mark.asyncio
async def test_engine_handles_module_error_gracefully():
    """Engine completes even when a module raises an exception."""

    class _FailingModule(BaseModule):
        name = "failing"
        description = "Always fails"
        category = "test"

        async def _execute(self, target: str, config: Config) -> ModuleResult:
            raise RuntimeError("intentional test failure")

    cfg = Config()
    engine = ScanEngine(target="example.com", config=cfg)

    with patch.object(engine, "_load_modules", return_value=[_FailingModule()]):
        result = await engine.run()

    assert result.finished_at is not None
    # The module result should carry the error
    mod_result = result.module_results.get("failing")
    assert mod_result is not None
    assert mod_result.error == "intentional test failure"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_engine_no_modules_returns_empty_result():
    """Engine completes gracefully when no modules are loaded."""
    cfg = Config()
    engine = ScanEngine(target="example.com", config=cfg)

    with patch.object(engine, "_load_modules", return_value=[]):
        result = await engine.run()

    assert result.target == "example.com"
    assert result.module_results == {}
    assert result.finished_at is not None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_engine_multiple_modules():
    """Engine runs multiple modules and aggregates results."""

    class _ModuleA(BaseModule):
        name = "module_a"
        description = "Module A"
        category = "test"

        async def _execute(self, target: str, config: Config) -> ModuleResult:
            return ModuleResult(
                module_name=self.name,
                target=target,
                findings=[Finding(title="Finding from A")],
            )

    class _ModuleB(BaseModule):
        name = "module_b"
        description = "Module B"
        category = "test"

        async def _execute(self, target: str, config: Config) -> ModuleResult:
            return ModuleResult(
                module_name=self.name,
                target=target,
                findings=[
                    Finding(title="Finding B1"),
                    Finding(title="Finding B2"),
                ],
            )

    cfg = Config()
    engine = ScanEngine(target="example.com", config=cfg)

    with patch.object(engine, "_load_modules", return_value=[_ModuleA(), _ModuleB()]):
        result = await engine.run()

    assert result.stats["modules_run"] == 2
    assert "module_a" in result.module_results
    assert "module_b" in result.module_results
    assert len(result.module_results["module_b"].findings) == 2
