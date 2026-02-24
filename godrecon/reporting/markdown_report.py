"""Markdown export for GODRECON scan results."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from godrecon.modules.base import Finding, ModuleResult

_SEV_BADGE = {
    "critical": "![CRITICAL](https://img.shields.io/badge/CRITICAL-red)",
    "high": "![HIGH](https://img.shields.io/badge/HIGH-orange)",
    "medium": "![MEDIUM](https://img.shields.io/badge/MEDIUM-yellow)",
    "low": "![LOW](https://img.shields.io/badge/LOW-blue)",
    "info": "![INFO](https://img.shields.io/badge/INFO-lightgrey)",
}

_SEV_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}


class MarkdownReporter:
    """Serialise scan results to a GitHub-flavored Markdown file."""

    def generate(self, results: Dict[str, Any], output_path: str) -> Path:
        """Write *results* as a Markdown document to *output_path*.

        Produces GitHub-flavored Markdown with severity badges, tables,
        and collapsible finding details.

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
        scan_date = (
            datetime.fromtimestamp(started_at, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            if started_at else "N/A"
        )

        # Collect all findings
        all_findings: List[Finding] = []
        for mr in results.get("module_results", {}).values():
            if isinstance(mr, ModuleResult):
                all_findings.extend(mr.findings)
            elif hasattr(mr, "findings"):
                all_findings.extend(mr.findings)

        sev_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in all_findings:
            k = f.severity.lower()
            sev_counts[k] = sev_counts.get(k, 0) + 1

        lines: List[str] = []

        # Header
        lines += [
            "# 🔍 GODRECON Security Report",
            "",
            f"> **Target:** `{target}`  ",
            f"> **Scan Date:** {scan_date}  ",
            f"> **Duration:** {duration:.1f}s  ",
            f"> **Total Findings:** {len(all_findings)}",
            "",
            "---",
            "",
        ]

        # Summary table
        lines += [
            "## 📊 Executive Summary",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        for sev in ["critical", "high", "medium", "low", "info"]:
            emoji = _SEV_EMOJI.get(sev, "")
            lines.append(f"| {emoji} **{sev.capitalize()}** | {sev_counts.get(sev, 0)} |")
        lines += ["", "---", ""]

        # Modules run
        modules_run = list(results.get("module_results", {}).keys())
        if modules_run:
            lines += [
                "## ⚙️ Modules Executed",
                "",
                " ".join(f"`{m}`" for m in modules_run),
                "",
                "---",
                "",
            ]

        # Findings by severity
        lines += ["## 🔎 Findings", ""]
        sev_order = ["critical", "high", "medium", "low", "info"]
        grouped: Dict[str, List[Finding]] = {s: [] for s in sev_order}
        for f in all_findings:
            grouped[f.severity.lower()].append(f)

        for sev in sev_order:
            group = grouped[sev]
            if not group:
                continue
            emoji = _SEV_EMOJI.get(sev, "")
            lines += [
                f"### {emoji} {sev.capitalize()} ({len(group)})",
                "",
                "| # | Title | Tags |",
                "|---|-------|------|",
            ]
            for i, f in enumerate(group, 1):
                tags = ", ".join(f'`{t}`' for t in f.tags[:4])
                title_escaped = f.title.replace("|", "&#124;")
                lines.append(f"| {i} | {title_escaped} | {tags} |")
            lines += [""]

            # Collapsible details for each finding
            for i, f in enumerate(group, 1):
                desc = (f.description or "").replace("\n", "  \n")
                lines += [
                    "<details>",
                    f"<summary><strong>{i}. {f.title}</strong></summary>",
                    "",
                    f"**Description:** {desc}",
                    "",
                ]
                if f.data:
                    lines += [
                        "**Evidence:**",
                        "```json",
                        str({k: v for k, v in list(f.data.items())[:5]})[:500],
                        "```",
                        "",
                    ]
                lines += ["</details>", ""]

        # Errors
        errors = results.get("errors", [])
        if errors:
            lines += ["---", "", "## ⚠️ Scan Errors", ""]
            for e in errors:
                lines.append(f"- `{e}`")
            lines.append("")

        # Footer
        lines += [
            "---",
            "",
            f"*Report generated by **GODRECON** on {scan_date}.*",
            "*This report is confidential and intended for authorised personnel only.*",
        ]

        path.write_text("\n".join(lines), encoding="utf-8")
        return path
