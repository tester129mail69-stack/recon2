"""SARIF report generator — Static Analysis Results Interchange Format."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from godrecon import __version__

_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


class SARIFReporter:
    """Generate a SARIF v2.1.0 report from GODRECON scan results."""

    def generate(self, data: dict, output_path: str) -> Path:
        """Write a SARIF v2.1.0 JSON file to *output_path*.

        Args:
            data: Scan result dictionary (same format used by other reporters).
            output_path: Destination file path.

        Returns:
            :class:`pathlib.Path` pointing to the written file.
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        rules: list[dict[str, Any]] = []
        results: list[dict[str, Any]] = []
        seen_rules: set[str] = set()

        module_results: dict[str, Any] = data.get("module_results", {})
        for mod_name, mod_result in module_results.items():
            rule_id = mod_name

            findings = []
            if mod_result is None:
                continue
            if hasattr(mod_result, "findings"):
                findings = mod_result.findings
            elif isinstance(mod_result, dict):
                findings = mod_result.get("findings", [])

            for finding in findings:
                if isinstance(finding, dict):
                    title = finding.get("title", "")
                    description = finding.get("description", "")
                    severity = (finding.get("severity") or "info").lower()
                else:
                    title = getattr(finding, "title", "")
                    description = getattr(finding, "description", "")
                    severity = (getattr(finding, "severity", "info") or "info").lower()

                level = _SEVERITY_TO_LEVEL.get(severity, "note")

                if rule_id not in seen_rules:
                    rules.append(
                        {
                            "id": rule_id,
                            "name": rule_id,
                            "shortDescription": {"text": f"Findings from {mod_name} module"},
                            "helpUri": "https://github.com/tester129mail69-stack/recon2",
                        }
                    )
                    seen_rules.add(rule_id)

                results.append(
                    {
                        "ruleId": rule_id,
                        "level": level,
                        "message": {
                            "text": f"{title}: {description}" if description else title,
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": data.get("target", "unknown"),
                                        "uriBaseId": "%SRCROOT%",
                                    },
                                },
                            }
                        ],
                        "properties": {
                            "severity": severity,
                        },
                    }
                )

        sarif_doc: dict[str, Any] = {
            "$schema": _SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "GODRECON",
                            "version": __version__,
                            "informationUri": "https://github.com/tester129mail69-stack/recon2",
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "properties": {
                        "target": data.get("target", "unknown"),
                        "generatedAt": datetime.now(timezone.utc).isoformat(),
                    },
                }
            ],
        }

        path.write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")
        return path
