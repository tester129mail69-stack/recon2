"""Tests for GODRECON reporting modules."""

from __future__ import annotations

import pytest

from godrecon.modules.base import Finding, ModuleResult
from godrecon.reporting.csv_report import CSVReporter
from godrecon.reporting.json_report import JSONReporter
from godrecon.reporting.markdown_report import MarkdownReporter


def _sample_results() -> dict:
    """Return a minimal scan-result dict suitable for all reporters."""
    finding = Finding(
        title="Test Finding",
        description="A test finding",
        severity="info",
        data={"host": "example.com"},
        tags=["test"],
    )
    module_result = ModuleResult(
        module_name="test_module",
        target="example.com",
        findings=[finding],
    )
    return {
        "target": "example.com",
        "started_at": 1700000000.0,
        "finished_at": 1700000010.0,
        "module_results": {"test_module": module_result},
        "errors": [],
    }


def test_json_reporter(tmp_path: pytest.TempPathFactory) -> None:
    """JSONReporter should produce a valid file."""
    output = str(tmp_path / "report.json")
    path = JSONReporter().generate(_sample_results(), output)
    assert path.exists()
    content = path.read_text()
    assert "example.com" in content


def test_csv_reporter(tmp_path: pytest.TempPathFactory) -> None:
    """CSVReporter should produce a valid file."""
    output = str(tmp_path / "report.csv")
    path = CSVReporter().generate(_sample_results(), output)
    assert path.exists()
    content = path.read_text()
    assert "title" in content.lower()


def test_markdown_reporter(tmp_path: pytest.TempPathFactory) -> None:
    """MarkdownReporter should produce a valid file."""
    output = str(tmp_path / "report.md")
    path = MarkdownReporter().generate(_sample_results(), output)
    assert path.exists()
    content = path.read_text()
    assert "example.com" in content


def test_html_reporter(tmp_path: pytest.TempPathFactory) -> None:
    """HTMLReporter should produce a valid file."""
    from godrecon.reporting.html import HTMLReporter

    output = str(tmp_path / "report.html")
    path = HTMLReporter().generate(_sample_results(), output)
    assert path.exists()
    content = path.read_text()
    assert "example.com" in content
