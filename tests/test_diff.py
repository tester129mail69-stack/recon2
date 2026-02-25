"""Tests for godrecon.core.diff."""

from __future__ import annotations

import pytest

from godrecon.core.diff import DiffResult, diff_scans


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_scan(
    *,
    subdomains: list[str] | None = None,
    ports: list[int] | None = None,
    findings: list[dict] | None = None,
) -> dict:
    """Build a minimal scan result dict for testing."""
    module_results: dict = {}

    if subdomains is not None:
        module_results["subdomains"] = {
            "raw": {"subdomains": subdomains},
            "findings": [],
        }

    if ports is not None:
        module_results["ports"] = {
            "raw": {"open_ports": ports},
            "findings": [],
        }

    if findings is not None:
        module_results["test_module"] = {
            "raw": {},
            "findings": findings,
        }

    return {"module_results": module_results}


# ---------------------------------------------------------------------------
# Identical scans
# ---------------------------------------------------------------------------


def test_identical_scans_no_diff():
    finding = {"title": "Test Finding", "severity": "info", "tags": []}
    scan = _make_scan(
        subdomains=["a.example.com"],
        ports=[80, 443],
        findings=[finding],
    )
    result = diff_scans(scan, scan)
    assert result.new_findings == []
    assert result.removed_findings == []
    assert len(result.unchanged_findings) == 1
    assert result.new_subdomains == set()
    assert result.removed_subdomains == set()
    assert result.new_ports == set()
    assert result.removed_ports == set()


# ---------------------------------------------------------------------------
# Empty scans
# ---------------------------------------------------------------------------


def test_empty_scans():
    scan_a: dict = {"module_results": {}}
    scan_b: dict = {"module_results": {}}
    result = diff_scans(scan_a, scan_b)
    assert isinstance(result, DiffResult)
    assert result.new_findings == []
    assert result.removed_findings == []
    assert result.new_subdomains == set()
    assert result.new_ports == set()


def test_diff_from_empty_to_populated():
    scan_a: dict = {"module_results": {}}
    scan_b = _make_scan(
        subdomains=["new.example.com"],
        ports=[80],
        findings=[{"title": "New Finding", "severity": "high", "tags": []}],
    )
    result = diff_scans(scan_a, scan_b)
    assert len(result.new_findings) == 1
    assert result.new_findings[0]["title"] == "New Finding"
    assert "new.example.com" in result.new_subdomains
    assert 80 in result.new_ports
    assert result.removed_findings == []
    assert result.removed_subdomains == set()
    assert result.removed_ports == set()


def test_diff_from_populated_to_empty():
    scan_a = _make_scan(
        subdomains=["old.example.com"],
        ports=[22],
        findings=[{"title": "Old Finding", "severity": "critical", "tags": []}],
    )
    scan_b: dict = {"module_results": {}}
    result = diff_scans(scan_a, scan_b)
    assert len(result.removed_findings) == 1
    assert "old.example.com" in result.removed_subdomains
    assert 22 in result.removed_ports
    assert result.new_findings == []


# ---------------------------------------------------------------------------
# Completely different scans
# ---------------------------------------------------------------------------


def test_completely_different_scans():
    scan_a = _make_scan(
        subdomains=["a1.example.com", "a2.example.com"],
        ports=[80, 443],
        findings=[{"title": "Finding A", "severity": "low", "tags": []}],
    )
    scan_b = _make_scan(
        subdomains=["b1.example.com"],
        ports=[8080],
        findings=[{"title": "Finding B", "severity": "high", "tags": []}],
    )
    result = diff_scans(scan_a, scan_b)
    assert len(result.new_findings) == 1
    assert len(result.removed_findings) == 1
    assert result.unchanged_findings == []
    assert result.new_subdomains == {"b1.example.com"}
    assert result.removed_subdomains == {"a1.example.com", "a2.example.com"}
    assert result.new_ports == {8080}
    assert result.removed_ports == {80, 443}


# ---------------------------------------------------------------------------
# Partial overlap
# ---------------------------------------------------------------------------


def test_partial_subdomain_overlap():
    scan_a = _make_scan(subdomains=["shared.example.com", "old.example.com"])
    scan_b = _make_scan(subdomains=["shared.example.com", "new.example.com"])
    result = diff_scans(scan_a, scan_b)
    assert result.new_subdomains == {"new.example.com"}
    assert result.removed_subdomains == {"old.example.com"}


def test_partial_port_overlap():
    scan_a = _make_scan(ports=[80, 443, 22])
    scan_b = _make_scan(ports=[80, 443, 3389])
    result = diff_scans(scan_a, scan_b)
    assert result.new_ports == {3389}
    assert result.removed_ports == {22}


# ---------------------------------------------------------------------------
# Summary dict
# ---------------------------------------------------------------------------


def test_summary_populated():
    scan_a = _make_scan(
        findings=[{"title": "F1", "severity": "info", "tags": []}],
        subdomains=["a.example.com"],
        ports=[80],
    )
    scan_b = _make_scan(
        findings=[
            {"title": "F1", "severity": "info", "tags": []},
            {"title": "F2", "severity": "high", "tags": []},
        ],
        subdomains=["a.example.com", "b.example.com"],
        ports=[80, 443],
    )
    result = diff_scans(scan_a, scan_b)
    s = result.summary
    assert s["new_findings"] == 1
    assert s["removed_findings"] == 0
    assert s["unchanged_findings"] == 1
    assert s["new_subdomains"] == 1
    assert s["removed_subdomains"] == 0
    assert s["new_ports"] == 1
    assert s["removed_ports"] == 0


# ---------------------------------------------------------------------------
# Port entries as dicts (with "port" key)
# ---------------------------------------------------------------------------


def test_ports_as_dict_entries():
    scan_a = _make_scan()
    scan_a["module_results"]["ports"] = {
        "raw": {"open_ports": [{"port": 80, "service": "http"}, {"port": 443}]},
        "findings": [],
    }
    scan_b = _make_scan()
    scan_b["module_results"]["ports"] = {
        "raw": {"open_ports": [{"port": 80, "service": "http"}]},
        "findings": [],
    }
    result = diff_scans(scan_a, scan_b)
    assert result.removed_ports == {443}
    assert result.new_ports == set()


# ---------------------------------------------------------------------------
# Subdomain case insensitivity
# ---------------------------------------------------------------------------


def test_subdomains_are_lowercased():
    scan_a = _make_scan(subdomains=["Sub.Example.COM"])
    scan_b = _make_scan(subdomains=["sub.example.com"])
    result = diff_scans(scan_a, scan_b)
    # Identical after lower-casing — no diff
    assert result.new_subdomains == set()
    assert result.removed_subdomains == set()
