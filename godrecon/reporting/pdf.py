"""PDF-ready HTML report generator for GODRECON.

Generates a self-contained HTML file with ``@media print`` CSS optimised
for printing to PDF via the browser's print dialog or headless Chrome.
The file is saved with an ``.html`` extension even if the output path ends
in ``.pdf``.
"""

from __future__ import annotations

import html as html_module
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from godrecon.modules.base import Finding, ModuleResult


def _esc(text: str) -> str:
    """HTML-escape a string."""
    return html_module.escape(str(text), quote=True)


def _collect_findings(results: Dict[str, Any]) -> List[Finding]:
    """Extract all Finding objects from scan results.

    Args:
        results: Top-level scan results dict.

    Returns:
        Flat list of all findings.
    """
    findings: List[Finding] = []
    for mr in results.get("module_results", {}).values():
        if isinstance(mr, ModuleResult):
            findings.extend(mr.findings)
        elif hasattr(mr, "findings"):
            findings.extend(mr.findings)
    return findings


_SEV_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#2563eb",
    "info": "#6b7280",
}


class PDFReporter:
    """Generate PDF-ready HTML reports from GODRECON scan results.

    Produces an HTML file with ``@media print`` CSS suitable for
    printing to PDF via a browser or headless renderer.
    """

    def generate(self, results: Dict[str, Any], output_path: str) -> Path:
        """Generate a PDF-ready HTML report.

        The output file always uses the ``.html`` extension even if *output_path*
        ends in ``.pdf``.

        Args:
            results: Scan result dictionary from the scan engine.
            output_path: Desired output path (extension will be normalised to .html).

        Returns:
            Path to the generated HTML file.
        """
        # Normalise extension
        p = Path(output_path)
        if p.suffix.lower() == ".pdf":
            p = p.with_suffix(".print.html")
        p.parent.mkdir(parents=True, exist_ok=True)

        target = results.get("target", "unknown")
        started_at = results.get("started_at", 0.0)
        finished_at = results.get("finished_at", 0.0)
        duration = (finished_at - started_at) if finished_at and started_at else 0.0
        scan_date = (
            datetime.fromtimestamp(started_at, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            if started_at else "N/A"
        )

        all_findings = sorted(
            _collect_findings(results),
            key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
                f.severity.lower(), 5
            ),
        )

        sev_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in all_findings:
            k = f.severity.lower()
            sev_counts[k] = sev_counts.get(k, 0) + 1

        findings_rows = self._render_findings(all_findings)
        sev_table = "\n".join(
            f"<tr><td class='sev-cell sev-{s}'>{s.capitalize()}</td><td>{c}</td></tr>"
            for s, c in sev_counts.items()
        )

        modules_run = ", ".join(results.get("module_results", {}).keys()) or "N/A"

        content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>GODRECON Security Report &mdash; {_esc(target)}</title>
<style>
/* ===== SCREEN STYLES ===== */
body{{font-family:Arial,Helvetica,sans-serif;font-size:11pt;color:#1a1a1a;background:#fff;margin:0;padding:0}}
.page{{max-width:800px;margin:0 auto;padding:24px 32px}}
h1{{font-size:22pt;color:#0f172a;margin:0 0 4px 0}}
h2{{font-size:14pt;color:#0f172a;margin:24px 0 8px;border-bottom:2px solid #e2e8f0;padding-bottom:4px}}
h3{{font-size:12pt;color:#334155;margin:16px 0 6px}}
.subtitle{{color:#64748b;font-size:10pt;margin-bottom:24px}}
.meta-grid{{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:24px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:16px}}
.meta-item{{font-size:10pt}}.meta-item strong{{color:#0f172a}}
.sev-table{{width:100%;border-collapse:collapse;margin-bottom:24px;font-size:10pt}}
.sev-table th{{background:#f1f5f9;padding:8px 12px;text-align:left;border:1px solid #e2e8f0;font-size:10pt}}
.sev-table td{{padding:7px 12px;border:1px solid #e2e8f0}}
.sev-cell{{font-weight:700;text-transform:uppercase;font-size:9pt}}
.sev-critical{{color:#dc2626}}.sev-high{{color:#ea580c}}.sev-medium{{color:#ca8a04}}
.sev-low{{color:#2563eb}}.sev-info{{color:#6b7280}}
.findings-table{{width:100%;border-collapse:collapse;font-size:9.5pt;margin-bottom:24px}}
.findings-table th{{background:#f1f5f9;padding:8px 10px;text-align:left;border:1px solid #e2e8f0;font-size:9pt;white-space:nowrap}}
.findings-table td{{padding:7px 10px;border:1px solid #e2e8f0;vertical-align:top;word-break:break-word}}
.findings-table tr:nth-child(even) td{{background:#fafafa}}
.badge{{display:inline-block;padding:2px 7px;border-radius:4px;font-size:8pt;font-weight:700;text-transform:uppercase}}
.badge-critical{{background:#fee2e2;color:#dc2626}}.badge-high{{background:#ffedd5;color:#ea580c}}
.badge-medium{{background:#fef9c3;color:#854d0e}}.badge-low{{background:#dbeafe;color:#1d4ed8}}
.badge-info{{background:#f1f5f9;color:#475569}}
.footer{{color:#94a3b8;font-size:8pt;text-align:center;margin-top:40px;padding-top:12px;border-top:1px solid #e2e8f0}}

/* ===== PRINT STYLES ===== */
@media print{{
  @page{{size:A4 portrait;margin:18mm 14mm 18mm 14mm}}
  body{{font-size:9.5pt;background:#fff}}
  .page{{max-width:100%;padding:0;margin:0}}
  h1{{font-size:18pt}}h2{{font-size:12pt}}h3{{font-size:11pt}}
  .meta-grid{{page-break-inside:avoid}}
  .sev-table{{page-break-inside:avoid}}
  .findings-table tr{{page-break-inside:avoid}}
  .no-print{{display:none}}
}}
</style>
</head>
<body>
<div class="page">
  <!-- COVER -->
  <h1>&#x1F50D; GODRECON Security Report</h1>
  <div class="subtitle">Automated Reconnaissance & Security Intelligence Report</div>

  <div class="meta-grid">
    <div class="meta-item"><strong>Target:</strong> {_esc(target)}</div>
    <div class="meta-item"><strong>Scan Date:</strong> {_esc(scan_date)}</div>
    <div class="meta-item"><strong>Duration:</strong> {duration:.1f} seconds</div>
    <div class="meta-item"><strong>Total Findings:</strong> {len(all_findings)}</div>
    <div class="meta-item"><strong>Modules Run:</strong> {_esc(modules_run)}</div>
    <div class="meta-item"><strong>Report Format:</strong> PDF-ready HTML</div>
  </div>

  <!-- SEVERITY SUMMARY -->
  <h2>Severity Summary</h2>
  <table class="sev-table">
    <thead><tr><th>Severity</th><th>Count</th></tr></thead>
    <tbody>{sev_table}</tbody>
  </table>

  <!-- FINDINGS -->
  <h2>Findings ({len(all_findings)})</h2>
  {findings_rows}

  <!-- FOOTER -->
  <div class="footer">
    Report generated by <strong>GODRECON</strong> on {_esc(scan_date)}<br>
    This report is confidential and intended for authorised personnel only.
  </div>
</div>

<div class="no-print" style="text-align:center;padding:16px;background:#f0f9ff;border:1px solid #bae6fd;margin:16px;border-radius:8px;color:#0369a1;font-size:13px">
  &#x1F4C4; To save as PDF: use your browser&rsquo;s <strong>File &rarr; Print</strong> and choose &ldquo;Save as PDF&rdquo;.
</div>
</body>
</html>"""
        p.write_text(content, encoding="utf-8")
        return p

    @staticmethod
    def _render_findings(findings: List[Finding]) -> str:
        """Render findings as an HTML table.

        Args:
            findings: List of Finding objects.

        Returns:
            HTML table string.
        """
        if not findings:
            return "<p><em>No findings recorded.</em></p>"

        rows = []
        for i, f in enumerate(findings, 1):
            sev = f.severity.lower()
            tags = ", ".join(f.tags[:4])
            desc = (f.description or "")[:300] + ("..." if len(f.description or "") > 300 else "")
            rows.append(
                f"<tr>"
                f"<td>{i}</td>"
                f"<td><span class='badge badge-{_esc(sev)}'>{_esc(sev)}</span></td>"
                f"<td><strong>{_esc(f.title)}</strong><br><span style='color:#64748b;font-size:9pt'>{_esc(desc)}</span></td>"
                f"<td style='color:#64748b;font-size:9pt'>{_esc(tags)}</td>"
                f"</tr>"
            )
        body = "\n".join(rows)
        return (
            "<table class='findings-table'>"
            "<thead><tr><th>#</th><th>Severity</th><th>Title / Description</th><th>Tags</th></tr></thead>"
            f"<tbody>{body}</tbody>"
            "</table>"
        )
