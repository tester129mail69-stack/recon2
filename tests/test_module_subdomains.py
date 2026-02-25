"""Tests for godrecon.modules.subdomains.aggregator."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from godrecon.core.config import Config
from godrecon.modules.base import ModuleResult
from godrecon.modules.subdomains.aggregator import SubdomainAggregator


@pytest.fixture()
def config() -> Config:
    cfg = Config()
    cfg.subdomains.bruteforce.enabled = False
    cfg.subdomains.permutation.enabled = False
    cfg.subdomains.recursive.enabled = False
    return cfg


def _make_dns_mock() -> MagicMock:
    mock = AsyncMock()
    mock.__aenter__ = AsyncMock(return_value=mock)
    mock.__aexit__ = AsyncMock(return_value=False)
    mock.detect_wildcard = AsyncMock(return_value=False)
    mock.bulk_resolve = AsyncMock(return_value={})
    return mock


def test_instantiation():
    mod = SubdomainAggregator()
    assert mod is not None


def test_attributes():
    mod = SubdomainAggregator()
    assert mod.name == "subdomains"
    assert mod.category == "discovery"
    assert mod.description


@pytest.mark.asyncio
async def test_execute_returns_module_result(config):
    dns_mock = _make_dns_mock()
    with (
        patch("godrecon.modules.subdomains.aggregator._build_sources", return_value=[]),
        patch(
            "godrecon.modules.subdomains.aggregator.AsyncDNSResolver",
            return_value=dns_mock,
        ),
        patch(
            "godrecon.modules.subdomains.aggregator.register_subdomains",
        ),
        patch(
            "godrecon.modules.subdomains.aggregator.get_notifier_from_config",
            return_value=None,
        ),
    ):
        mod = SubdomainAggregator()
        result = await mod._execute("example.com", config)

    assert isinstance(result, ModuleResult)
    assert result.module_name == "subdomains"
    assert result.target == "example.com"
    assert result.error is None


@pytest.mark.asyncio
async def test_execute_error_handling(config):
    with (
        patch(
            "godrecon.modules.subdomains.aggregator._build_sources",
            side_effect=RuntimeError("boom"),
        ),
        patch(
            "godrecon.modules.subdomains.aggregator.register_subdomains",
        ),
        patch(
            "godrecon.modules.subdomains.aggregator.get_notifier_from_config",
            return_value=None,
        ),
    ):
        mod = SubdomainAggregator()
        result = await mod.run("example.com", config)

    assert result.error is not None
    assert result.findings == []
