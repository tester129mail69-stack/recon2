"""HTML report generator for GODRECON."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict


class HTMLReporter:
    """Generate HTML reports from scan results using Jinja2 templates."""

    def generate(self, results: Dict[str, Any], output_path: str) -> Path:
        """Generate an HTML report.

        Args:
            results: Scan result dictionary.
            output_path: Destination file path.

        Returns:
            Path to the generated file.
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        target = results.get("target", "unknown")
        html = (
            "<!DOCTYPE html><html><head><meta charset='utf-8'>"
            f"<title>GODRECON — {target}</title></head><body>"
            f"<h1>GODRECON Scan Report</h1><p>Target: {target}</p>"
            "</body></html>"
        )
        path.write_text(html, encoding="utf-8")
        return path
