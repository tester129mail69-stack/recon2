"""Tests for godrecon.modules.cors.scanner."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from godrecon.core.config import Config
from godrecon.modules.base import ModuleResult
from godrecon.modules.cors.scanner import CORSModule


def test_instantiation():
    mod = CORSModule()
    assert mod.name == "cors"
    assert mod.category == "vulns"
    assert mod.version == "1.0.0"


def test_build_finding_reflected_with_credentials():
    """Should return high severity finding for reflected origin + credentials."""
    check_result = {
        "status": 200,
        "acao": "https://evil.com",
        "acac": True,
        "acam": "GET, POST",
        "origin_sent": "https://evil.com",
    }
    finding = CORSModule._build_finding(check_result, "https://example.com", "https://evil.com", "evil_origin")
    assert finding is not None
    assert finding.severity == "high"


def test_build_finding_null_with_credentials():
    """Should return medium severity finding for null origin + credentials."""
    check_result = {
        "status": 200,
        "acao": "null",
        "acac": True,
        "acam": "GET",
        "origin_sent": "null",
    }
    finding = CORSModule._build_finding(check_result, "https://example.com", "null", "null_origin")
    assert finding is not None
    assert finding.severity == "medium"


def test_build_finding_no_acao():
    """No finding when ACAO header absent."""
    check_result = {"status": 200, "acao": "", "acac": False, "acam": "", "origin_sent": "https://evil.com"}
    finding = CORSModule._build_finding(check_result, "https://example.com", "https://evil.com", "test")
    assert finding is None


def test_build_finding_low_severity():
    """Reflected origin without credentials is low severity."""
    check_result = {
        "status": 200,
        "acao": "https://evil.com",
        "acac": False,
        "acam": "GET",
        "origin_sent": "https://evil.com",
    }
    finding = CORSModule._build_finding(check_result, "https://example.com", "https://evil.com", "test")
    assert finding is not None
    assert finding.severity == "low"


@pytest.mark.asyncio
async def test_execute_with_vulnerability():
    """Execute should find high-severity CORS issue."""
    mock_result = {
        "status": 200,
        "acao": "https://evil.com",
        "acac": True,
        "acam": "GET, POST",
        "origin_sent": "https://evil.com",
    }
    mod = CORSModule()
    with patch.object(CORSModule, "_check_cors", new=AsyncMock(return_value=mock_result)):
        result = await mod._execute("example.com", Config())
    assert isinstance(result, ModuleResult)
    assert len(result.findings) > 0


@pytest.mark.asyncio
async def test_execute_no_vulnerability():
    """Execute should return no findings when CORS is properly configured."""
    mock_result = {
        "status": 200,
        "acao": "",
        "acac": False,
        "acam": "",
        "origin_sent": "https://evil.com",
    }
    mod = CORSModule()
    with patch.object(CORSModule, "_check_cors", new=AsyncMock(return_value=mock_result)):
        result = await mod._execute("example.com", Config())
    assert isinstance(result, ModuleResult)
    assert result.findings == []
