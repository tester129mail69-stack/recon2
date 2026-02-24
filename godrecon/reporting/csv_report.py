"""CSV export for GODRECON scan findings."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, List

from godrecon.modules.base import Finding, ModuleResult

_FIELDNAMES = [
    "severity",
    "category",
    "title",
    "description",
    "target",
    "evidence",
    "recommendation",
    "module",
    "tags",
]

_RECOMMENDATIONS: Dict[str, str] = {
    "critical": "Remediate immediately. Escalate to security team.",
    "high": "Address as high priority within current sprint.",
    "medium": "Schedule remediation in the next release cycle.",
    "low": "Address as part of routine security maintenance.",
    "info": "Review for context; no immediate action required.",
}


class CSVReporter:
    """Serialise scan findings to a CSV file."""

    def generate(self, results: Dict[str, Any], output_path: str) -> Path:
        """Write findings from *results* as CSV to *output_path*.

        Columns: severity, category, title, description, target, evidence,
        recommendation, module, tags.

        Args:
            results: Scan result dictionary containing ``module_results``.
            output_path: Destination file path.

        Returns:
            Path to the generated file.
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        target = results.get("target", "")
        rows: List[Dict[str, str]] = []

        for module_name, module_result in results.get("module_results", {}).items():
            findings: List[Finding] = []
            if isinstance(module_result, ModuleResult):
                findings = module_result.findings
            elif hasattr(module_result, "findings"):
                findings = module_result.findings

            for finding in findings:
                category = finding.tags[0] if finding.tags else "general"
                try:
                    evidence = json.dumps(finding.data, default=str)[:500]
                except Exception:
                    evidence = str(finding.data)[:500]
                recommendation = _RECOMMENDATIONS.get(
                    finding.severity.lower(), "Review and address appropriately."
                )
                rows.append({
                    "severity": finding.severity,
                    "category": category,
                    "title": finding.title,
                    "description": finding.description,
                    "target": target,
                    "evidence": evidence,
                    "recommendation": recommendation,
                    "module": module_name,
                    "tags": ", ".join(finding.tags),
                })

        # Sort by severity
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        rows.sort(key=lambda r: sev_order.get(r["severity"].lower(), 5))

        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=_FIELDNAMES)
            writer.writeheader()
            writer.writerows(rows)

        return path
