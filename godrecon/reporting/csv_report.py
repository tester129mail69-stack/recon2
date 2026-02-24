"""CSV export for GODRECON scan findings."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Dict, List


class CSVReporter:
    """Serialise scan findings to a CSV file."""

    def generate(self, results: Dict[str, Any], output_path: str) -> Path:
        """Write findings from *results* as CSV to *output_path*.

        Args:
            results: Scan result dictionary containing ``module_results``.
            output_path: Destination file path.

        Returns:
            Path to the generated file.
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        rows: List[Dict[str, str]] = []
        for module_name, module_result in results.get("module_results", {}).items():
            if hasattr(module_result, "findings"):
                for finding in module_result.findings:
                    rows.append(
                        {
                            "module": module_name,
                            "title": finding.title,
                            "severity": finding.severity,
                            "description": finding.description,
                        }
                    )

        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(
                fh, fieldnames=["module", "title", "severity", "description"]
            )
            writer.writeheader()
            writer.writerows(rows)

        return path
