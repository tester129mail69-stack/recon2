"""Tests for godrecon.modules.wayback.scanner."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from godrecon.core.config import Config
from godrecon.modules.base import ModuleResult
from godrecon.modules.wayback.scanner import WaybackModule


def test_instantiation():
    mod = WaybackModule()
    assert mod.name == "wayback"
    assert mod.category == "osint"


def test_categorize_urls():
    urls = [
        "https://example.com/api/users",
        "https://example.com/admin",
        "https://example.com/index.html",
    ]
    result = WaybackModule._categorize_urls(urls)
    assert "https://example.com/api/users" in result["api_endpoints"]
    assert "https://example.com/admin" in result["admin_panels"]


def test_find_interesting():
    urls = [
        "https://example.com/admin/login",
        "https://example.com/page",
    ]
    interesting = WaybackModule._find_interesting(urls)
    assert len(interesting) == 1
    assert "https://example.com/admin/login" in interesting


@pytest.mark.asyncio
async def test_execute_returns_result():
    mod = WaybackModule()
    with patch.object(
        WaybackModule,
        "_fetch_cdx",
        new=AsyncMock(return_value=["https://example.com/api/users", "https://example.com/admin"]),
    ):
        result = await mod._execute("example.com", Config())
    assert isinstance(result, ModuleResult)


@pytest.mark.asyncio
async def test_execute_empty_results():
    mod = WaybackModule()
    with patch.object(
        WaybackModule,
        "_fetch_cdx",
        new=AsyncMock(return_value=[]),
    ):
        result = await mod._execute("example.com", Config())
    assert isinstance(result, ModuleResult)
    assert result.findings == []
