"""Tests for godrecon.reporting.sarif."""

from __future__ import annotations

import json
from pathlib import Path

from godrecon.modules.base import Finding, ModuleResult
from godrecon.reporting.sarif import _SEVERITY_TO_LEVEL, SARIFReporter


def _sample_data() -> dict:
    f_critical = Finding(title="RCE", description="Remote code execution", severity="critical", data={}, tags=[])
    f_medium = Finding(title="XSS", description="Cross-site scripting", severity="medium", data={}, tags=[])
    f_info = Finding(title="Open Port", description="Port 80", severity="info", data={}, tags=[])
    mr = ModuleResult(module_name="vulns", target="example.com", findings=[f_critical, f_medium, f_info])
    return {
        "target": "example.com",
        "module_results": {"vulns": mr},
        "errors": [],
    }


def test_sarif_output_is_valid_json(tmp_path: Path):
    output = str(tmp_path / "report.sarif")
    SARIFReporter().generate(_sample_data(), output)
    content = Path(output).read_text()
    parsed = json.loads(content)
    assert isinstance(parsed, dict)


def test_sarif_version(tmp_path: Path):
    output = str(tmp_path / "report.sarif")
    SARIFReporter().generate(_sample_data(), output)
    doc = json.loads(Path(output).read_text())
    assert doc["version"] == "2.1.0"


def test_sarif_schema_field(tmp_path: Path):
    output = str(tmp_path / "report.sarif")
    SARIFReporter().generate(_sample_data(), output)
    doc = json.loads(Path(output).read_text())
    assert "$schema" in doc
    assert "sarif" in doc["$schema"].lower()


def test_sarif_tool_name(tmp_path: Path):
    output = str(tmp_path / "report.sarif")
    SARIFReporter().generate(_sample_data(), output)
    doc = json.loads(Path(output).read_text())
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "GODRECON"


def test_sarif_findings_mapped(tmp_path: Path):
    output = str(tmp_path / "report.sarif")
    SARIFReporter().generate(_sample_data(), output)
    doc = json.loads(Path(output).read_text())
    results = doc["runs"][0]["results"]
    assert len(results) == 3


def test_sarif_severity_mapping(tmp_path: Path):
    output = str(tmp_path / "report.sarif")
    SARIFReporter().generate(_sample_data(), output)
    doc = json.loads(Path(output).read_text())
    results = doc["runs"][0]["results"]
    levels = {r["level"] for r in results}
    # critical → error, medium → warning, info → note
    assert "error" in levels
    assert "warning" in levels
    assert "note" in levels


def test_sarif_severity_mapping_constants():
    assert _SEVERITY_TO_LEVEL["critical"] == "error"
    assert _SEVERITY_TO_LEVEL["high"] == "error"
    assert _SEVERITY_TO_LEVEL["medium"] == "warning"
    assert _SEVERITY_TO_LEVEL["low"] == "note"
    assert _SEVERITY_TO_LEVEL["info"] == "note"


def test_sarif_rules_contain_module_name(tmp_path: Path):
    output = str(tmp_path / "report.sarif")
    SARIFReporter().generate(_sample_data(), output)
    doc = json.loads(Path(output).read_text())
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = {r["id"] for r in rules}
    assert "vulns" in rule_ids


def test_sarif_empty_data(tmp_path: Path):
    output = str(tmp_path / "report.sarif")
    SARIFReporter().generate({"target": "t", "module_results": {}, "errors": []}, output)
    doc = json.loads(Path(output).read_text())
    assert doc["runs"][0]["results"] == []


def test_sarif_returns_path(tmp_path: Path):
    output = str(tmp_path / "report.sarif")
    result = SARIFReporter().generate(_sample_data(), output)
    assert isinstance(result, Path)
    assert result.exists()
