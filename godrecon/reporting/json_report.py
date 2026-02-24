"""JSON export for GODRECON scan results."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from godrecon.modules.base import Finding, ModuleResult


def _serialize_finding(f: Finding) -> Dict[str, Any]:
    """Convert a Finding to a JSON-serialisable dict.

    Args:
        f: Finding object.

    Returns:
        Dict representation.
    """
    return {
        "title": f.title,
        "description": f.description,
        "severity": f.severity,
        "data": f.data,
        "tags": f.tags,
    }


def _serialize_module_result(mr: ModuleResult) -> Dict[str, Any]:
    """Convert a ModuleResult to a JSON-serialisable dict.

    Args:
        mr: ModuleResult object.

    Returns:
        Dict representation.
    """
    return {
        "module_name": mr.module_name,
        "target": mr.target,
        "duration": mr.duration,
        "error": mr.error,
        "findings": [_serialize_finding(f) for f in mr.findings],
        "raw": mr.raw,
    }


class JSONReporter:
    """Serialise scan results to a structured JSON file."""

    def generate(self, results: Dict[str, Any], output_path: str) -> Path:
        """Write *results* as pretty-printed JSON to *output_path*.

        The output includes full scan metadata, all findings, and per-severity
        summary statistics.

        Args:
            results: Scan result dictionary.
            output_path: Destination file path.

        Returns:
            Path to the generated file.
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        target = results.get("target", "unknown")
        started_at = results.get("started_at", 0.0)
        finished_at = results.get("finished_at", 0.0)
        duration = (finished_at - started_at) if finished_at and started_at else 0.0

        all_findings: List[Finding] = []
        serialized_modules: Dict[str, Any] = {}
        for mod_name, mr in results.get("module_results", {}).items():
            if isinstance(mr, ModuleResult):
                all_findings.extend(mr.findings)
                serialized_modules[mod_name] = _serialize_module_result(mr)
            else:
                serialized_modules[mod_name] = mr

        sev_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in all_findings:
            k = f.severity.lower()
            sev_counts[k] = sev_counts.get(k, 0) + 1

        report: Dict[str, Any] = {
            "meta": {
                "tool": "GODRECON",
                "version": "1.0.0",
                "report_generated_at": datetime.now(timezone.utc).isoformat(),
            },
            "scan": {
                "target": target,
                "scan_start": started_at,
                "scan_end": finished_at,
                "duration_seconds": round(duration, 2),
                "modules_run": list(results.get("module_results", {}).keys()),
                "errors": results.get("errors", []),
            },
            "summary": {
                "total_findings": len(all_findings),
                "findings_by_severity": sev_counts,
            },
            "findings": [_serialize_finding(f) for f in all_findings],
            "module_results": serialized_modules,
        }

        path.write_text(
            json.dumps(report, indent=2, default=str), encoding="utf-8"
        )
        return path

