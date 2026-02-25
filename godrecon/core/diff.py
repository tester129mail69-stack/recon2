"""Scan result diffing — compare two scans to detect changes."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Set


@dataclass
class DiffResult:
    """The result of comparing two scan outputs.

    Attributes:
        new_findings: Findings present in scan B but not in scan A.
        removed_findings: Findings present in scan A but not in scan B.
        unchanged_findings: Findings present in both scans.
        new_subdomains: Subdomains discovered in scan B but not in scan A.
        removed_subdomains: Subdomains in scan A that are absent from scan B.
        new_ports: Open ports found in scan B but not in scan A.
        removed_ports: Open ports in scan A that are closed/missing in scan B.
        summary: Human-readable statistics dict.
    """

    new_findings: List[Dict[str, Any]] = field(default_factory=list)
    removed_findings: List[Dict[str, Any]] = field(default_factory=list)
    unchanged_findings: List[Dict[str, Any]] = field(default_factory=list)
    new_subdomains: Set[str] = field(default_factory=set)
    removed_subdomains: Set[str] = field(default_factory=set)
    new_ports: Set[int] = field(default_factory=set)
    removed_ports: Set[int] = field(default_factory=set)
    summary: Dict[str, Any] = field(default_factory=dict)


def _extract_subdomains(scan: Dict[str, Any]) -> Set[str]:
    """Return the set of subdomains contained in *scan*.

    Looks in ``scan["module_results"]["subdomains"]["raw"]["subdomains"]``
    and in finding data tagged with ``"subdomain"``.

    Args:
        scan: Scan result dict as produced by the engine.

    Returns:
        Set of subdomain strings (lower-cased).
    """
    subdomains: Set[str] = set()
    module_results = scan.get("module_results") or {}

    # Primary: raw subdomains list from the subdomains module
    subs_result = module_results.get("subdomains") or {}
    raw = subs_result.get("raw") or {}
    for sub in raw.get("subdomains", []):
        if isinstance(sub, str):
            subdomains.add(sub.lower())

    # Secondary: check findings tagged "subdomain"
    for _mod_name, mod_result in module_results.items():
        if not mod_result:
            continue
        for finding in (mod_result.get("findings") or []):
            if "subdomain" in (finding.get("tags") or []):
                data = finding.get("data") or {}
                for key in ("subdomain", "host", "name"):
                    val = data.get(key)
                    if isinstance(val, str):
                        subdomains.add(val.lower())

    return subdomains


def _extract_ports(scan: Dict[str, Any]) -> Set[int]:
    """Return the set of open TCP ports contained in *scan*.

    Looks in ``scan["module_results"]["ports"]["raw"]["open_ports"]``.

    Args:
        scan: Scan result dict as produced by the engine.

    Returns:
        Set of port numbers (integers).
    """
    ports: Set[int] = set()
    module_results = scan.get("module_results") or {}
    ports_result = module_results.get("ports") or {}
    raw = ports_result.get("raw") or {}

    for entry in raw.get("open_ports", []):
        if isinstance(entry, int):
            ports.add(entry)
        elif isinstance(entry, dict):
            port = entry.get("port")
            if isinstance(port, int):
                ports.add(port)

    return ports


def _normalise_finding(finding: Dict[str, Any]) -> str:
    """Return a stable string key for *finding*.

    Uses ``title`` + ``severity`` as the identity fingerprint so that
    findings with the same meaning compare equal regardless of description
    changes or whitespace.

    Args:
        finding: Finding dict.

    Returns:
        Stable string key.
    """
    return f"{finding.get('title', '')}::{finding.get('severity', 'info')}"


def _collect_all_findings(scan: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Flatten all findings from every module in *scan*.

    Args:
        scan: Scan result dict.

    Returns:
        Flat list of finding dicts.
    """
    findings: List[Dict[str, Any]] = []
    module_results = scan.get("module_results") or {}
    for mod_result in module_results.values():
        if not mod_result:
            continue
        for f in (mod_result.get("findings") or []):
            findings.append(f)
    return findings


def diff_scans(scan_a: Dict[str, Any], scan_b: Dict[str, Any]) -> DiffResult:
    """Compare two scan result dicts and return a :class:`DiffResult`.

    Args:
        scan_a: Earlier (baseline) scan result dict.
        scan_b: Later (comparison) scan result dict.

    Returns:
        A :class:`DiffResult` detailing what changed between the two scans.
    """
    findings_a = _collect_all_findings(scan_a)
    findings_b = _collect_all_findings(scan_b)

    keys_a: Dict[str, Dict[str, Any]] = {_normalise_finding(f): f for f in findings_a}
    keys_b: Dict[str, Dict[str, Any]] = {_normalise_finding(f): f for f in findings_b}

    set_a = set(keys_a)
    set_b = set(keys_b)

    new_findings = [keys_b[k] for k in (set_b - set_a)]
    removed_findings = [keys_a[k] for k in (set_a - set_b)]
    unchanged_findings = [keys_a[k] for k in (set_a & set_b)]

    subs_a = _extract_subdomains(scan_a)
    subs_b = _extract_subdomains(scan_b)

    ports_a = _extract_ports(scan_a)
    ports_b = _extract_ports(scan_b)

    result = DiffResult(
        new_findings=new_findings,
        removed_findings=removed_findings,
        unchanged_findings=unchanged_findings,
        new_subdomains=subs_b - subs_a,
        removed_subdomains=subs_a - subs_b,
        new_ports=ports_b - ports_a,
        removed_ports=ports_a - ports_b,
    )
    result.summary = {
        "new_findings": len(new_findings),
        "removed_findings": len(removed_findings),
        "unchanged_findings": len(unchanged_findings),
        "new_subdomains": len(result.new_subdomains),
        "removed_subdomains": len(result.removed_subdomains),
        "new_ports": len(result.new_ports),
        "removed_ports": len(result.removed_ports),
    }
    return result
