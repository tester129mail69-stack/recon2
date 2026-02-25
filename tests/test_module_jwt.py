"""Tests for godrecon.modules.jwt.scanner."""
from __future__ import annotations

import base64
import json
from unittest.mock import AsyncMock, patch

import pytest

from godrecon.core.config import Config
from godrecon.modules.base import ModuleResult
from godrecon.modules.jwt.scanner import JWTModule


def _make_jwt(header: dict, payload: dict) -> str:
    """Create a fake JWT for testing."""
    def b64enc(d: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{b64enc(header)}.{b64enc(payload)}.fakesig"


def test_instantiation():
    mod = JWTModule()
    assert mod.name == "jwt"
    assert mod.category == "vulns"
    assert mod.version == "1.0.0"


def test_decode_jwt():
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "user123", "iat": 1700000000}
    jwt_str = _make_jwt(header, payload)
    h, p = JWTModule._decode_jwt(jwt_str)
    assert h == header
    assert p == payload


def test_analyze_jwt_alg_none():
    """Should detect alg:none vulnerability."""
    jwt_str = _make_jwt({"alg": "none", "typ": "JWT"}, {"sub": "user123", "exp": 9999999999})
    vulns = JWTModule._analyze_jwt(jwt_str)
    types = [v["type"] for v in vulns]
    assert "Algorithm None Attack" in types


def test_analyze_jwt_missing_exp():
    """Should detect missing exp claim."""
    jwt_str = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "user123"})
    vulns = JWTModule._analyze_jwt(jwt_str)
    types = [v["type"] for v in vulns]
    assert "Missing Expiration Claim" in types


def test_analyze_jwt_sensitive_data():
    """Should detect sensitive keys in payload."""
    jwt_str = _make_jwt({"alg": "HS256"}, {"sub": "user", "password": "s3cr3t", "exp": 9999999999})
    vulns = JWTModule._analyze_jwt(jwt_str)
    types = [v["type"] for v in vulns]
    assert "Sensitive Data in Payload" in types


def test_analyze_jwt_clean():
    """Should return no vulns for a well-formed JWT."""
    jwt_str = _make_jwt(
        {"alg": "RS256", "typ": "JWT"},
        {"sub": "user123", "exp": 9999999999, "iss": "https://auth.example.com"},
    )
    vulns = JWTModule._analyze_jwt(jwt_str)
    assert vulns == []


@pytest.mark.asyncio
async def test_execute_with_jwt():
    """Should analyze collected JWTs and return findings."""
    # JWT with alg:none
    jwt_str = _make_jwt({"alg": "none"}, {"sub": "user"})
    mod = JWTModule()
    with patch.object(JWTModule, "_collect_jwts", new=AsyncMock(return_value=[jwt_str])):
        result = await mod._execute("example.com", Config())
    assert isinstance(result, ModuleResult)
    assert len(result.findings) > 0


@pytest.mark.asyncio
async def test_execute_no_jwts():
    """Should return empty findings when no JWTs found."""
    mod = JWTModule()
    with patch.object(JWTModule, "_collect_jwts", new=AsyncMock(return_value=[])):
        result = await mod._execute("example.com", Config())
    assert isinstance(result, ModuleResult)
    assert result.findings == []
    assert result.raw["jwts_found"] == 0
