"""Tests for godrecon.modules.ssl.scanner."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from godrecon.core.config import Config
from godrecon.modules.base import ModuleResult
from godrecon.modules.ssl.scanner import SSLAnalysisModule


def test_instantiation():
    mod = SSLAnalysisModule()
    assert mod is not None


def test_attributes():
    mod = SSLAnalysisModule()
    assert mod.name == "ssl"
    assert mod.category == "ssl"
    assert mod.description


@pytest.mark.asyncio
async def test_execute_no_tls_services():
    analyzer_mock = MagicMock()
    analyzer_mock.analyze = AsyncMock(return_value={"error": "connection refused"})

    with patch(
        "godrecon.modules.ssl.scanner.SSLAnalyzer",
        return_value=analyzer_mock,
    ):
        mod = SSLAnalysisModule()
        result = await mod._execute("example.com", Config())

    assert isinstance(result, ModuleResult)
    assert result.module_name == "ssl"
    assert result.error is None
    assert any("No TLS Services" in f.title for f in result.findings)


@pytest.mark.asyncio
async def test_execute_with_ssl_result():
    ssl_data = {
        "host": "example.com",
        "port": 443,
        "grade": "A",
        "score": 95,
        "certificate": {"expired": False, "days_until_expiry": 200, "self_signed": False, "wildcard": False},
        "protocols": {},
        "ciphers": [],
        "vulnerabilities": {},
    }
    analyzer_mock = MagicMock()
    analyzer_mock.analyze = AsyncMock(return_value=ssl_data)

    with patch(
        "godrecon.modules.ssl.scanner.SSLAnalyzer",
        return_value=analyzer_mock,
    ):
        mod = SSLAnalysisModule()
        result = await mod._execute("example.com", Config())

    assert isinstance(result, ModuleResult)
    assert result.error is None
    assert len(result.findings) > 0


@pytest.mark.asyncio
async def test_execute_error_handling():
    with patch(
        "godrecon.modules.ssl.scanner.SSLAnalyzer",
        side_effect=RuntimeError("ssl error"),
    ):
        mod = SSLAnalysisModule()
        result = await mod.run("example.com", Config())

    assert result.error is not None
    assert result.findings == []
