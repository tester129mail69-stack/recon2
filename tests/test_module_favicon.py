"""Tests for godrecon.modules.favicon.scanner."""
from __future__ import annotations

import base64
from unittest.mock import AsyncMock, patch

import pytest

from godrecon.core.config import Config
from godrecon.modules.base import ModuleResult
from godrecon.modules.favicon.scanner import FaviconModule, _FAVICON_DB


def test_instantiation():
    mod = FaviconModule()
    assert mod.name == "favicon"
    assert mod.category == "recon"
    assert mod.version == "1.0.0"


def test_favicon_db_has_entries():
    """Favicon DB should have at least 30 entries."""
    assert len(_FAVICON_DB) >= 30


def test_compute_hashes_returns_tuple():
    """_compute_hashes should return (mmh3_hash, md5_hash, technology)."""
    fake_data = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09"
    mmh3_hash, md5_hash, technology = FaviconModule._compute_hashes(fake_data)
    assert isinstance(mmh3_hash, int)
    assert isinstance(md5_hash, str)
    assert len(md5_hash) == 32
    # technology is None or a string
    assert technology is None or isinstance(technology, str)


@pytest.mark.asyncio
async def test_execute_with_favicon():
    """Should return finding when favicon found."""
    mod = FaviconModule()
    fake_favicon = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    with patch.object(FaviconModule, "_fetch_favicon", new=AsyncMock(return_value=fake_favicon)):
        result = await mod._execute("example.com", Config())
    assert isinstance(result, ModuleResult)
    assert len(result.findings) == 1
    assert "mmh3_hash" in result.raw


@pytest.mark.asyncio
async def test_execute_no_favicon():
    """Should return empty findings when favicon not found."""
    mod = FaviconModule()
    with patch.object(FaviconModule, "_fetch_favicon", new=AsyncMock(return_value=None)):
        result = await mod._execute("example.com", Config())
    assert isinstance(result, ModuleResult)
    assert result.findings == []
    assert result.raw.get("favicon_found") is False


@pytest.mark.asyncio
async def test_execute_known_technology():
    """Should identify known technology from favicon hash."""
    mod = FaviconModule()

    # Patch _compute_hashes to return a known hash
    with patch.object(
        FaviconModule,
        "_compute_hashes",
        return_value=(-1074136313, "abc123md5", "WordPress"),
    ):
        with patch.object(FaviconModule, "_fetch_favicon", new=AsyncMock(return_value=b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")):
            result = await mod._execute("example.com", Config())

    assert isinstance(result, ModuleResult)
    assert len(result.findings) == 1
    assert result.raw.get("technology") == "WordPress"
