"""Tests for godrecon.modules.waf.scanner."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from godrecon.core.config import Config
from godrecon.modules.base import ModuleResult
from godrecon.modules.waf.scanner import WAFDetectorModule


def test_instantiation():
    mod = WAFDetectorModule()
    assert mod.name == "waf"
    assert mod.category == "http"
    assert mod.version == "1.0.0"


def test_check_signatures_cloudflare():
    """Should detect CloudFlare from cf-ray header."""
    resp = {
        "status": 200,
        "headers": {"cf-ray": "abc123-LAX"},
        "cookies": {},
    }
    result = WAFDetectorModule._check_signatures(resp)
    assert result is not None
    assert result["name"] == "CloudFlare"
    assert result["confidence"] == "high"


def test_check_signatures_no_match():
    """No WAF signatures should return None."""
    resp = {
        "status": 200,
        "headers": {"content-type": "text/html"},
        "cookies": {},
    }
    result = WAFDetectorModule._check_signatures(resp)
    assert result is None


def test_check_signatures_imperva_cookie():
    """Should detect Imperva from cookie."""
    resp = {
        "status": 200,
        "headers": {},
        "cookies": {"incap_ses_123": "abc"},
    }
    result = WAFDetectorModule._check_signatures(resp)
    assert result is not None
    assert result["name"] == "Imperva/Incapsula"


@pytest.mark.asyncio
async def test_execute_detects_waf():
    """Should detect WAF and create finding."""
    mock_resp = {
        "status": 200,
        "headers": {"cf-ray": "abc123-LAX", "server": "cloudflare"},
        "cookies": {},
    }
    mod = WAFDetectorModule()
    with patch.object(WAFDetectorModule, "_fetch", new=AsyncMock(return_value=mock_resp)):
        result = await mod._execute("example.com", Config())
    assert isinstance(result, ModuleResult)
    assert result.raw["waf_detected"] is True
    assert len(result.findings) >= 1


@pytest.mark.asyncio
async def test_execute_no_waf():
    """Should return no-WAF finding when nothing detected."""
    mock_resp = {
        "status": 200,
        "headers": {"content-type": "text/html"},
        "cookies": {},
    }
    mod = WAFDetectorModule()
    with patch.object(WAFDetectorModule, "_fetch", new=AsyncMock(return_value=mock_resp)):
        result = await mod._execute("example.com", Config())
    assert isinstance(result, ModuleResult)
    assert result.raw["waf_detected"] is False


@pytest.mark.asyncio
async def test_execute_handles_fetch_error():
    """Should handle fetch errors gracefully."""
    mod = WAFDetectorModule()
    with patch.object(WAFDetectorModule, "_fetch", new=AsyncMock(return_value=None)):
        result = await mod._execute("example.com", Config())
    assert isinstance(result, ModuleResult)
    assert result.error is None
