"""Tests for godrecon.modules.whois.scanner."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from godrecon.core.config import Config
from godrecon.modules.base import ModuleResult
from godrecon.modules.whois.scanner import WHOISModule

_SAMPLE_WHOIS = (
    "Domain Name: EXAMPLE.COM\r\n"
    "Registrar: Example Registrar\r\n"
    "Creation Date: 2020-01-01\r\n"
    "Registry Expiry Date: 2025-01-01\r\n"
    "Name Server: ns1.example.com\r\n"
)


def test_instantiation():
    mod = WHOISModule()
    assert mod.name == "whois"
    assert mod.category == "osint"


def test_parse_whois():
    mod = WHOISModule()
    parsed = mod._parse_whois(_SAMPLE_WHOIS)

    assert parsed["domain_name"] == "EXAMPLE.COM"
    assert parsed["registrar"] == "Example Registrar"
    assert parsed["creation_date"] == "2020-01-01"
    assert parsed["expiry_date"] == "2025-01-01"
    assert "ns1.example.com" in parsed["name_servers"]


@pytest.mark.asyncio
async def test_execute_returns_result():
    mock_reader = MagicMock()
    mock_reader.read = AsyncMock(return_value=_SAMPLE_WHOIS.encode())
    mock_writer = MagicMock()
    mock_writer.drain = AsyncMock()
    mock_writer.wait_closed = AsyncMock()

    with patch(
        "asyncio.open_connection",
        new=AsyncMock(return_value=(mock_reader, mock_writer)),
    ):
        mod = WHOISModule()
        result = await mod._execute("example.com", Config())

    assert isinstance(result, ModuleResult)
    assert result.module_name == "whois"
    assert result.error is None


@pytest.mark.asyncio
async def test_execute_handles_error():
    with patch.object(
        WHOISModule,
        "_whois_query",
        new=AsyncMock(side_effect=OSError("connection refused")),
    ):
        mod = WHOISModule()
        result = await mod._execute("example.com", Config())

    assert isinstance(result, ModuleResult)
    assert result.error is None  # errors are caught internally; module does not crash
