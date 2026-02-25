"""Tests for godrecon.modules.ports.scanner."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from godrecon.core.config import Config
from godrecon.modules.base import ModuleResult
from godrecon.modules.ports.scanner import PortScannerModule


def test_instantiation():
    mod = PortScannerModule()
    assert mod is not None


def test_attributes():
    mod = PortScannerModule()
    assert mod.name == "ports"
    assert mod.category == "ports"
    assert mod.description


@pytest.mark.asyncio
async def test_execute_no_open_ports():
    fingerprinter_mock = MagicMock()
    fingerprinter_mock.fingerprint = MagicMock(return_value={"service": "unknown"})

    scan_all_mock = AsyncMock(return_value=[])

    with (
        patch.object(PortScannerModule, "_scan_all", scan_all_mock),
        patch(
            "godrecon.modules.ports.scanner.ServiceFingerprinter.load_services",
            return_value=fingerprinter_mock,
        ),
        patch(
            "godrecon.modules.ports.scanner._load_ports_json",
            return_value={"top100": [80, 443]},
        ),
    ):
        mod = PortScannerModule()
        result = await mod._execute("example.com", Config())

    assert isinstance(result, ModuleResult)
    assert result.module_name == "ports"
    assert result.error is None


@pytest.mark.asyncio
async def test_execute_with_open_port():
    fingerprinter_mock = MagicMock()
    fingerprinter_mock.fingerprint = MagicMock(
        return_value={"service": "http", "protocol": "tcp", "description": "HTTP"}
    )

    banner_mock = MagicMock()
    banner_mock.grab = AsyncMock(return_value=None)

    open_ports = [{"port": 80, "state": "open", "latency": 0.01}]
    scan_all_mock = AsyncMock(return_value=open_ports)

    with (
        patch.object(PortScannerModule, "_scan_all", scan_all_mock),
        patch(
            "godrecon.modules.ports.scanner.ServiceFingerprinter.load_services",
            return_value=fingerprinter_mock,
        ),
        patch(
            "godrecon.modules.ports.scanner.BannerGrabber",
            return_value=banner_mock,
        ),
        patch(
            "godrecon.modules.ports.scanner._load_ports_json",
            return_value={"top100": [80, 443]},
        ),
    ):
        mod = PortScannerModule()
        result = await mod._execute("example.com", Config())

    assert isinstance(result, ModuleResult)
    assert result.error is None
    assert len(result.findings) > 0


@pytest.mark.asyncio
async def test_execute_error_handling():
    with patch(
        "godrecon.modules.ports.scanner._load_ports_json",
        side_effect=RuntimeError("disk error"),
    ):
        mod = PortScannerModule()
        result = await mod.run("example.com", Config())

    assert result.error is not None
