"""Markdown export for GODRECON scan results."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict


class MarkdownReporter:
    """Serialise scan results to a Markdown file."""

    def generate(self, results: Dict[str, Any], output_path: str) -> Path:
        """Write *results* as a Markdown document to *output_path*.

        Args:
            results: Scan result dictionary.
            output_path: Destination file path.

        Returns:
            Path to the generated file.
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        target = results.get("target", "unknown")
        lines = [
            f"# GODRECON Scan Report",
            f"",
            f"**Target:** `{target}`",
            f"",
            f"## Summary",
            f"",
        ]

        stats = results.get("stats", {})
        for k, v in stats.items():
            lines.append(f"- **{k}:** {v}")

        lines += ["", "## Module Results", ""]
        for module_name, module_result in results.get("module_results", {}).items():
            lines.append(f"### {module_name}")
            if hasattr(module_result, "findings"):
                for finding in module_result.findings:
                    lines.append(
                        f"- [{finding.severity.upper()}] **{finding.title}**: "
                        f"{finding.description}"
                    )
            lines.append("")

        path.write_text("\n".join(lines), encoding="utf-8")
        return path
