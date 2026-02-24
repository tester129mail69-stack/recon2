"""Tests for godrecon.core.engine."""

from __future__ import annotations

import pkgutil
from unittest.mock import MagicMock, patch

import pytest

import godrecon.modules as modules_pkg
from godrecon.core.config import Config
from godrecon.core.engine import ScanEngine, ScanResult


def test_engine_initialises_with_target():
    engine = ScanEngine(target="example.com", config=Config())
    assert engine.target == "example.com"
    assert engine.scope.in_scope("example.com")


def test_engine_initialises_with_config():
    cfg = Config()
    engine = ScanEngine(target="example.com", config=cfg)
    assert engine.config is cfg


def test_scan_result_duration():
    import time

    result = ScanResult(target="example.com", started_at=time.time() - 5)
    assert result.duration >= 5
    result.finished_at = result.started_at + 3
    assert abs(result.duration - 3) < 0.01


def test_module_discovery_finds_packages():
    """Engine discovers all sub-packages under godrecon/modules/."""
    discovered = [
        name
        for _, name, ispkg in pkgutil.iter_modules(modules_pkg.__path__)
        if ispkg
    ]
    expected = [
        "api_intel", "cloud", "content_discovery", "crawl", "dns",
        "email_sec", "http", "network", "osint", "ports",
        "screenshots", "ssl", "subdomains", "takeover", "tech", "visual", "vulns",
    ]
    for mod in expected:
        assert mod in discovered, f"Module '{mod}' not found in modules package"


def test_engine_on_event_registers_handler():
    engine = ScanEngine(target="example.com", config=Config())
    handler = MagicMock()
    engine.on_event(handler)
    assert handler in engine._event_handlers


@pytest.mark.asyncio
async def test_engine_run_no_modules_loaded():
    """Engine completes gracefully when no modules can be loaded."""
    engine = ScanEngine(target="example.com", config=Config())
    with patch.object(engine, "_load_modules", return_value=[]):
        result = await engine.run()
    assert result.target == "example.com"
    assert result.finished_at is not None
    assert result.module_results == {}
