"""Tests for godrecon.modules.crawl.scanner."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from godrecon.core.config import Config
from godrecon.modules.base import ModuleResult
from godrecon.modules.crawl.scanner import WebCrawlModule


def _make_http_mock() -> MagicMock:
    mock = AsyncMock()
    mock.__aenter__ = AsyncMock(return_value=mock)
    mock.__aexit__ = AsyncMock(return_value=False)
    return mock


def test_instantiation():
    mod = WebCrawlModule()
    assert mod is not None


def test_attributes():
    mod = WebCrawlModule()
    assert mod.name == "crawl"
    assert mod.category == "crawl"
    assert mod.description


@pytest.mark.asyncio
async def test_execute_returns_module_result():
    http_mock = _make_http_mock()
    spider_mock = MagicMock()
    spider_mock.crawl = AsyncMock(
        return_value={
            "pages": [],
            "forms": [],
            "scripts": [],
            "links": [],
            "comments": [],
        }
    )

    with (
        patch(
            "godrecon.modules.crawl.scanner.AsyncHTTPClient",
            return_value=http_mock,
        ),
        patch(
            "godrecon.modules.crawl.scanner.WebSpider",
            return_value=spider_mock,
        ),
    ):
        mod = WebCrawlModule()
        result = await mod._execute("example.com", Config())

    assert isinstance(result, ModuleResult)
    assert result.module_name == "crawl"
    assert result.error is None


@pytest.mark.asyncio
async def test_execute_error_handling():
    with patch(
        "godrecon.modules.crawl.scanner.AsyncHTTPClient",
        side_effect=RuntimeError("http error"),
    ):
        mod = WebCrawlModule()
        result = await mod.run("example.com", Config())

    assert result.error is not None
    assert result.findings == []
