"""Scan result differ/comparator for GODRECON continuous monitoring.

Compares two scan results and produces a structured diff summary including
new findings, resolved findings, severity changes, new subdomains, and new
open ports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class FindingDiff:
    """Represents a single finding change between two scans.

    Attributes:
        title: Finding title/description.
        severity: Severity level string.
        module: Module that produced the finding.
        category: Finding category.
        target: Affected target.
    """

    title: str
    severity: str
    module: str = ""
    category: str = ""
    target: str = ""


@dataclass
class DiffSummary:
    """Summary of differences between two scan results.

    Attributes:
        new_findings: Findings present in the new scan but not the old.
        resolved_findings: Findings present in the old scan but not the new.
        new_subdomains: Subdomains discovered in the new scan but not the old.
        resolved_subdomains: Subdomains no longer present.
        new_ports: Port/host combos new in this scan.
        resolved_ports: Port/host combos no longer present.
        severity_counts: Count of new findings by severity level.
        total_new: Total new findings count.
        total_resolved: Total resolved findings count.
    """

    new_findings: List[FindingDiff] = field(default_factory=list)
    resolved_findings: List[FindingDiff] = field(default_factory=list)
    new_subdomains: List[str] = field(default_factory=list)
    resolved_subdomains: List[str] = field(default_factory=list)
    new_ports: List[str] = field(default_factory=list)
    resolved_ports: List[str] = field(default_factory=list)
    severity_counts: Dict[str, int] = field(default_factory=dict)
    total_new: int = 0
    total_resolved: int = 0

    @property
    def has_changes(self) -> bool:
        """Return True if any changes were detected."""
        return bool(
            self.new_findings
            or self.resolved_findings
            or self.new_subdomains
            or self.resolved_subdomains
            or self.new_ports
            or self.resolved_ports
        )


def _extract_findings(scan_data: Dict[str, Any]) -> List[FindingDiff]:
    """Extract a flat list of FindingDiff objects from raw scan data.

    Args:
        scan_data: Raw scan result dictionary (as returned by the engine or
                   loaded from JSON).

    Returns:
        Flat list of :class:`FindingDiff` items.
    """
    findings: List[FindingDiff] = []
    module_results = scan_data.get("module_results", {})
    for module_name, module_result in module_results.items():
        raw_findings: List[Any] = []
        if isinstance(module_result, dict):
            raw_findings = module_result.get("findings", [])
        elif hasattr(module_result, "findings"):
            raw_findings = module_result.findings or []

        for f in raw_findings:
            if isinstance(f, dict):
                findings.append(
                    FindingDiff(
                        title=str(f.get("title", f.get("description", ""))),
                        severity=str(f.get("severity", "info")).lower(),
                        module=module_name,
                        category=str(f.get("category", "")),
                        target=str(f.get("target", "")),
                    )
                )
            elif hasattr(f, "title"):
                findings.append(
                    FindingDiff(
                        title=str(getattr(f, "title", "")),
                        severity=str(getattr(f, "severity", "info")).lower(),
                        module=module_name,
                        category=str(getattr(f, "category", "")),
                        target=str(getattr(f, "target", "")),
                    )
                )
    return findings


def _extract_subdomains(scan_data: Dict[str, Any]) -> List[str]:
    """Extract discovered subdomains from scan data.

    Args:
        scan_data: Raw scan result dictionary.

    Returns:
        List of subdomain strings.
    """
    subdomains: List[str] = []
    module_results = scan_data.get("module_results", {})
    sub_result = module_results.get("subdomains", {})
    if isinstance(sub_result, dict):
        data = sub_result.get("data", {})
        if isinstance(data, dict):
            subdomains = list(data.get("subdomains", []))
        elif isinstance(data, list):
            subdomains = [str(s) for s in data]
    elif hasattr(sub_result, "data"):
        data = getattr(sub_result, "data", {}) or {}
        if isinstance(data, dict):
            subdomains = list(data.get("subdomains", []))
    return subdomains


def _extract_ports(scan_data: Dict[str, Any]) -> List[str]:
    """Extract open port entries from scan data as 'host:port' strings.

    Args:
        scan_data: Raw scan result dictionary.

    Returns:
        List of ``'host:port'`` strings.
    """
    ports: List[str] = []
    module_results = scan_data.get("module_results", {})
    port_result = module_results.get("ports", {})
    if isinstance(port_result, dict):
        data = port_result.get("data", {})
        if isinstance(data, dict):
            for host, host_data in data.items():
                if isinstance(host_data, dict):
                    for port in host_data.get("open_ports", []):
                        ports.append(f"{host}:{port}")
    elif hasattr(port_result, "data"):
        data = getattr(port_result, "data", {}) or {}
        if isinstance(data, dict):
            for host, host_data in data.items():
                if isinstance(host_data, dict):
                    for port in host_data.get("open_ports", []):
                        ports.append(f"{host}:{port}")
    return ports


def _finding_key(f: FindingDiff) -> str:
    """Return a stable identity key for a finding.

    Args:
        f: The finding diff object.

    Returns:
        String key combining severity, module, and title.
    """
    return f"{f.severity}|{f.module}|{f.title}"


class ScanDiffer:
    """Compares two scan results and produces a structured :class:`DiffSummary`.

    Example::

        differ = ScanDiffer()
        summary = differ.diff(old_scan_data, new_scan_data)
        if summary.has_changes:
            print(f"New findings: {summary.total_new}")
    """

    def diff(
        self,
        old_scan: Optional[Dict[str, Any]],
        new_scan: Dict[str, Any],
    ) -> DiffSummary:
        """Compare *old_scan* against *new_scan* and return a diff.

        Args:
            old_scan: Previous scan result dict, or ``None`` for a first-run.
            new_scan: Current scan result dict.

        Returns:
            Populated :class:`DiffSummary`.
        """
        summary = DiffSummary()

        if old_scan is None:
            # First run — treat everything as new
            new_findings = _extract_findings(new_scan)
            summary.new_findings = new_findings
            summary.new_subdomains = _extract_subdomains(new_scan)
            summary.new_ports = _extract_ports(new_scan)
        else:
            old_findings = {_finding_key(f): f for f in _extract_findings(old_scan)}
            new_findings = {_finding_key(f): f for f in _extract_findings(new_scan)}

            summary.new_findings = [
                f for k, f in new_findings.items() if k not in old_findings
            ]
            summary.resolved_findings = [
                f for k, f in old_findings.items() if k not in new_findings
            ]

            old_subs = set(_extract_subdomains(old_scan))
            new_subs = set(_extract_subdomains(new_scan))
            summary.new_subdomains = sorted(new_subs - old_subs)
            summary.resolved_subdomains = sorted(old_subs - new_subs)

            old_ports = set(_extract_ports(old_scan))
            new_ports = set(_extract_ports(new_scan))
            summary.new_ports = sorted(new_ports - old_ports)
            summary.resolved_ports = sorted(old_ports - new_ports)

        # Severity counts for new findings
        for f in summary.new_findings:
            sev = f.severity.lower()
            summary.severity_counts[sev] = summary.severity_counts.get(sev, 0) + 1

        summary.total_new = len(summary.new_findings)
        summary.total_resolved = len(summary.resolved_findings)
        return summary
