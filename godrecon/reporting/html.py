"""HTML report generator for GODRECON."""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from godrecon.ai.scorer import RiskScorer
from godrecon.modules.base import Finding, ModuleResult


_SEVERITY_COLORS = {
    "critical": "#ff3333",
    "high": "#ff8c00",
    "medium": "#ffd700",
    "low": "#4a9eff",
    "info": "#8b949e",
}


def _collect_findings(results: Dict[str, Any]) -> List[Finding]:
    """Extract all findings from module results.

    Args:
        results: Top-level scan results dict.

    Returns:
        Flat list of all Finding objects.
    """
    findings: List[Finding] = []
    for module_result in results.get("module_results", {}).values():
        if isinstance(module_result, ModuleResult):
            findings.extend(module_result.findings)
        elif isinstance(module_result, dict):
            for f in module_result.get("findings", []):
                if isinstance(f, Finding):
                    findings.append(f)
    return findings


def _severity_order(sev: str) -> int:
    """Return sort key for severity (critical first)."""
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(sev.lower(), 5)


def _esc(text: str) -> str:
    """HTML-escape a string."""
    return html.escape(str(text), quote=True)


class HTMLReporter:
    """Generate beautiful self-contained HTML reports from GODRECON scan results."""

    def generate(self, results: Dict[str, Any], output_path: str) -> Path:
        """Generate a complete self-contained HTML report.

        Args:
            results: Scan result dictionary from the scan engine.
            output_path: File path to write the report to.

        Returns:
            Path to the generated HTML file.
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        target = results.get("target", "unknown")
        started_at = results.get("started_at", 0.0)
        finished_at = results.get("finished_at", 0.0)
        duration = finished_at - started_at if finished_at and started_at else 0.0
        scan_date = (
            datetime.fromtimestamp(started_at, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            if started_at else "N/A"
        )

        all_findings = sorted(_collect_findings(results), key=lambda f: _severity_order(f.severity))

        sev_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in all_findings:
            k = f.severity.lower()
            sev_counts[k] = sev_counts.get(k, 0) + 1

        risk_score = int(RiskScorer().score(all_findings))

        cat_counts: Dict[str, int] = {}
        for f in all_findings:
            cat = f.tags[0] if f.tags else "general"
            cat_counts[cat] = cat_counts.get(cat, 0) + 1

        modules_run = list(results.get("module_results", {}).keys())
        errors = results.get("errors", [])
        total = len(all_findings)

        if risk_score >= 80:
            risk_class, risk_label = "risk-critical", "CRITICAL RISK"
        elif risk_score >= 60:
            risk_class, risk_label = "risk-high", "HIGH RISK"
        elif risk_score >= 40:
            risk_class, risk_label = "risk-medium", "MEDIUM RISK"
        elif risk_score >= 20:
            risk_class, risk_label = "risk-low", "LOW RISK"
        else:
            risk_class, risk_label = "risk-info", "MINIMAL RISK"

        severity_chart = self._render_severity_chart(sev_counts)
        category_chart = self._render_category_chart(cat_counts)
        findings_table = self._render_findings_table(all_findings)
        modules_badges = " ".join(f'<span class="module-badge">{_esc(m)}</span>' for m in modules_run)

        errors_section = ""
        if errors:
            li_items = "\n".join(f"<li>{_esc(str(e))}</li>" for e in errors)
            errors_section = f'<div class="card err-card"><h3>Scan Errors</h3><ul>{li_items}</ul></div>'

        report_html = self._build_html(
            target=target, scan_date=scan_date, duration=duration, total=total,
            risk_score=risk_score, risk_class=risk_class, risk_label=risk_label,
            sev_counts=sev_counts, severity_chart=severity_chart,
            category_chart=category_chart, findings_table=findings_table,
            modules_badges=modules_badges, errors_section=errors_section,
        )
        path.write_text(report_html, encoding="utf-8")
        return path

    @staticmethod
    def _build_html(**ctx: Any) -> str:
        """Build the complete HTML document string.

        Args:
            **ctx: Template context variables.

        Returns:
            Complete HTML document as string.
        """
        t = ctx["target"]
        scan_date = ctx["scan_date"]
        duration = ctx["duration"]
        total = ctx["total"]
        risk_score = ctx["risk_score"]
        risk_class = ctx["risk_class"]
        risk_label = ctx["risk_label"]
        sev = ctx["sev_counts"]
        severity_chart = ctx["severity_chart"]
        category_chart = ctx["category_chart"]
        findings_table = ctx["findings_table"]
        modules_badges = ctx["modules_badges"]
        errors_section = ctx["errors_section"]

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GODRECON Report &mdash; {_esc(t)}</title>
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
html{{font-size:14px;scroll-behavior:smooth}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;background:#0d1117;color:#c9d1d9;line-height:1.6;min-height:100vh}}
::-webkit-scrollbar{{width:6px;height:6px}}::-webkit-scrollbar-track{{background:#161b22}}::-webkit-scrollbar-thumb{{background:#30363d;border-radius:3px}}::-webkit-scrollbar-thumb:hover{{background:#58a6ff}}
.header{{background:linear-gradient(135deg,#0d1117 0%,#161b22 50%,#0d1117 100%);border-bottom:1px solid #21262d;position:sticky;top:0;z-index:100;box-shadow:0 2px 16px rgba(0,0,0,.4)}}
.header-inner{{max-width:1400px;margin:0 auto;padding:16px 24px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px}}
.logo{{display:flex;align-items:center;gap:12px}}
.logo-icon{{width:40px;height:40px;background:linear-gradient(135deg,#58a6ff,#00ff41);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:18px;font-weight:800;color:#0d1117;flex-shrink:0}}
.logo-text{{font-size:20px;font-weight:700;color:#f0f6fc;letter-spacing:2px}}
.logo-sub{{font-size:11px;color:#58a6ff;letter-spacing:1px;text-transform:uppercase}}
.header-meta{{display:flex;gap:16px;flex-wrap:wrap;align-items:center}}
.meta-item{{font-size:12px;color:#8b949e}}.meta-item strong{{color:#c9d1d9}}
.main{{max-width:1400px;margin:0 auto;padding:24px}}
.card{{background:#161b22;border:1px solid #21262d;border-radius:10px;padding:20px 24px;margin-bottom:20px;transition:border-color .2s}}
.card:hover{{border-color:#30363d}}
.card-title{{font-size:16px;font-weight:600;color:#f0f6fc;margin-bottom:16px;display:flex;align-items:center;gap:8px}}
.grid-2{{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:20px}}
.grid-4{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px}}
.stat-box{{background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:16px;text-align:center;transition:transform .15s,border-color .2s}}
.stat-box:hover{{transform:translateY(-2px);border-color:#58a6ff}}
.stat-value{{font-size:32px;font-weight:700;line-height:1.1;margin-bottom:4px}}
.stat-label{{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#8b949e}}
.stat-critical{{color:#ff3333;border-color:rgba(255,51,51,.3)}}
.stat-high{{color:#ff8c00;border-color:rgba(255,140,0,.3)}}
.stat-medium{{color:#ffd700;border-color:rgba(255,215,0,.3)}}
.stat-low{{color:#4a9eff;border-color:rgba(74,158,255,.3)}}
.stat-info{{color:#8b949e;border-color:#30363d}}
.gauge-container{{display:flex;flex-direction:column;align-items:center;padding:12px}}
.gauge-score{{font-size:52px;font-weight:800;line-height:1;margin-bottom:4px}}
.gauge-label{{font-size:13px;font-weight:600;letter-spacing:2px;text-transform:uppercase;margin-bottom:16px}}
.risk-critical .gauge-score,.risk-critical .gauge-label{{color:#ff3333}}
.risk-high .gauge-score,.risk-high .gauge-label{{color:#ff8c00}}
.risk-medium .gauge-score,.risk-medium .gauge-label{{color:#ffd700}}
.risk-low .gauge-score,.risk-low .gauge-label{{color:#4a9eff}}
.risk-info .gauge-score,.risk-info .gauge-label{{color:#8b949e}}
.gauge-bar-bg{{width:100%;height:8px;background:#21262d;border-radius:4px;overflow:hidden;max-width:280px}}
.gauge-bar-fill{{height:100%;border-radius:4px}}
.risk-critical .gauge-bar-fill{{background:linear-gradient(90deg,#ff6666,#ff3333)}}
.risk-high .gauge-bar-fill{{background:linear-gradient(90deg,#ffaa44,#ff8c00)}}
.risk-medium .gauge-bar-fill{{background:linear-gradient(90deg,#ffe066,#ffd700)}}
.risk-low .gauge-bar-fill{{background:linear-gradient(90deg,#7ab8ff,#4a9eff)}}
.risk-info .gauge-bar-fill{{background:linear-gradient(90deg,#a0a8b0,#8b949e)}}
.badge{{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;white-space:nowrap}}
.badge-critical{{background:rgba(255,51,51,.2);color:#ff3333;border:1px solid rgba(255,51,51,.4)}}
.badge-high{{background:rgba(255,140,0,.2);color:#ff8c00;border:1px solid rgba(255,140,0,.4)}}
.badge-medium{{background:rgba(255,215,0,.15);color:#ffd700;border:1px solid rgba(255,215,0,.4)}}
.badge-low{{background:rgba(74,158,255,.15);color:#4a9eff;border:1px solid rgba(74,158,255,.4)}}
.badge-info{{background:rgba(139,148,158,.15);color:#8b949e;border:1px solid rgba(139,148,158,.4)}}
.findings-controls{{display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap;align-items:center}}
.search-input{{flex:1;min-width:200px;background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:8px 12px;color:#c9d1d9;font-size:13px;outline:none;transition:border-color .2s}}
.search-input:focus{{border-color:#58a6ff}}.search-input::placeholder{{color:#484f58}}
.filter-btn{{background:#21262d;border:1px solid #30363d;border-radius:6px;padding:7px 12px;color:#c9d1d9;font-size:12px;cursor:pointer;transition:all .2s;white-space:nowrap}}
.filter-btn:hover{{background:#30363d;border-color:#58a6ff}}
.filter-btn.active{{background:#1f3a5f;border-color:#58a6ff;color:#58a6ff}}
.findings-table-wrap{{overflow-x:auto}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
thead{{background:#0d1117;position:sticky;top:73px;z-index:10}}
th{{padding:10px 14px;text-align:left;color:#8b949e;font-size:11px;text-transform:uppercase;letter-spacing:.8px;border-bottom:1px solid #21262d;cursor:pointer;user-select:none;white-space:nowrap}}
th:hover{{color:#58a6ff}}.sort-icon{{font-size:10px;margin-left:4px;opacity:.5}}th.sorted .sort-icon{{opacity:1;color:#58a6ff}}
td{{padding:10px 14px;border-bottom:1px solid #161b22;vertical-align:top;max-width:400px}}
tr:hover td{{background:rgba(88,166,255,.04)}}tr.finding-row{{cursor:pointer}}
.finding-title{{color:#f0f6fc;font-weight:500;word-break:break-word}}
.finding-desc{{color:#8b949e;font-size:12px;margin-top:3px;word-break:break-word}}
.finding-tags{{margin-top:4px;display:flex;flex-wrap:wrap;gap:4px}}
.tag{{display:inline-block;background:#21262d;color:#8b949e;border-radius:10px;padding:1px 7px;font-size:10px}}
.finding-details{{display:none;background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:12px;margin-top:8px;font-size:11px;color:#8b949e;font-family:'Courier New',monospace;white-space:pre-wrap;word-break:break-all;max-height:200px;overflow-y:auto}}
.module-badge{{display:inline-block;background:#1f3a5f;color:#58a6ff;border:1px solid #1a4a8a;border-radius:12px;padding:3px 10px;font-size:11px;margin:2px}}
.section-divider{{display:flex;align-items:center;gap:12px;margin:28px 0 16px}}
.section-divider h2{{font-size:18px;font-weight:600;color:#f0f6fc;white-space:nowrap}}
.section-divider::after{{content:'';flex:1;height:1px;background:#21262d}}
.no-findings{{text-align:center;padding:48px;color:#484f58}}
.err-card{{border-left:3px solid #ff8c00;margin-top:20px}}.err-card h3{{color:#ff8c00;margin-bottom:12px}}
.footer{{text-align:center;padding:32px 24px;color:#484f58;font-size:12px;border-top:1px solid #21262d;margin-top:40px}}
@media(max-width:768px){{.header-inner{{padding:12px 16px}}.main{{padding:16px}}.grid-4{{grid-template-columns:repeat(2,1fr)}}th,td{{padding:8px 10px}}.findings-controls{{flex-direction:column}}.search-input{{min-width:100%}}}}
</style>
</head>
<body>
<header class="header">
  <div class="header-inner">
    <div class="logo">
      <div class="logo-icon">GR</div>
      <div><div class="logo-text">GODRECON</div><div class="logo-sub">Security Intelligence</div></div>
    </div>
    <div class="header-meta">
      <span class="meta-item">Target: <strong>{_esc(t)}</strong></span>
      <span class="meta-item">Date: <strong>{_esc(scan_date)}</strong></span>
      <span class="meta-item">Duration: <strong>{duration:.1f}s</strong></span>
      <span class="meta-item">Findings: <strong>{total}</strong></span>
    </div>
  </div>
</header>
<main class="main">
  <div class="section-divider"><h2>&#x1F4CA; Executive Summary</h2></div>
  <div class="grid-2">
    <div class="card">
      <div class="card-title">&#x1F3AF; Risk Score</div>
      <div class="gauge-container {_esc(risk_class)}">
        <div class="gauge-score">{risk_score}</div>
        <div class="gauge-label">{_esc(risk_label)}</div>
        <div class="gauge-bar-bg"><div class="gauge-bar-fill" style="width:{risk_score}%"></div></div>
      </div>
    </div>
    <div class="card">
      <div class="card-title">&#x1F4C8; Severity Distribution</div>
      <div class="grid-4" style="margin-bottom:16px">
        <div class="stat-box stat-critical"><div class="stat-value">{sev.get("critical",0)}</div><div class="stat-label">Critical</div></div>
        <div class="stat-box stat-high"><div class="stat-value">{sev.get("high",0)}</div><div class="stat-label">High</div></div>
        <div class="stat-box stat-medium"><div class="stat-value">{sev.get("medium",0)}</div><div class="stat-label">Medium</div></div>
        <div class="stat-box stat-low"><div class="stat-value">{sev.get("low",0)}</div><div class="stat-label">Low</div></div>
      </div>
      {severity_chart}
    </div>
  </div>
  <div class="grid-2">
    <div class="card">
      <div class="card-title">&#x2699;&#xFE0F; Modules Executed</div>
      <div style="padding:4px 0">{modules_badges if modules_badges else '<span style="color:#484f58">None recorded.</span>'}</div>
    </div>
    <div class="card">
      <div class="card-title">&#x1F4C2; Findings by Category</div>
      {category_chart}
    </div>
  </div>
  {errors_section}
  <div class="section-divider"><h2>&#x1F50D; Findings ({total})</h2></div>
  <div class="card">
    <div class="findings-controls">
      <input type="text" class="search-input" id="searchInput" placeholder="Search findings..." oninput="filterFindings()">
      <button class="filter-btn active" onclick="filterBySev('all',this)">All</button>
      <button class="filter-btn" onclick="filterBySev('critical',this)">Critical</button>
      <button class="filter-btn" onclick="filterBySev('high',this)">High</button>
      <button class="filter-btn" onclick="filterBySev('medium',this)">Medium</button>
      <button class="filter-btn" onclick="filterBySev('low',this)">Low</button>
      <button class="filter-btn" onclick="filterBySev('info',this)">Info</button>
    </div>
    {findings_table}
  </div>
</main>
<footer class="footer">
  <p>Generated by <strong>GODRECON</strong> Security Intelligence Platform &mdash; {_esc(scan_date)}</p>
  <p style="margin-top:6px;font-size:11px">This report is confidential and intended for authorised personnel only.</p>
</footer>
<script>
let curSev='all';
function filterFindings(){{
  const q=document.getElementById('searchInput').value.toLowerCase();
  document.querySelectorAll('.finding-row').forEach(r=>{{
    const s=(r.dataset.severity||'').toLowerCase();
    const ok=(curSev==='all'||s===curSev)&&(!q||r.textContent.toLowerCase().includes(q));
    r.style.display=ok?'':'none';
    const d=r.nextElementSibling;
    if(d&&d.classList.contains('detail-row'))d.style.display='none';
  }});
}}
function filterBySev(s,btn){{
  curSev=s;
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  filterFindings();
}}
function toggleDetail(i){{
  const d=document.getElementById('detail-'+i);
  if(d)d.style.display=d.style.display==='none'?'block':'none';
}}
let sortCol=-1,sortAsc=true;
function sortTable(c){{
  const tb=document.getElementById('findingsBody');if(!tb)return;
  const rows=Array.from(tb.querySelectorAll('tr.finding-row'));
  const ths=document.querySelectorAll('th[data-col]');
  if(sortCol===c)sortAsc=!sortAsc;else{{sortCol=c;sortAsc=true;}}
  ths.forEach(h=>{{h.classList.remove('sorted');h.querySelector('.sort-icon').textContent='⇅';}});
  const ah=document.querySelector('th[data-col="'+c+'"]');
  if(ah){{ah.classList.add('sorted');ah.querySelector('.sort-icon').textContent=sortAsc?'↑':'↓';}}
  const so={{critical:0,high:1,medium:2,low:3,info:4}};
  rows.sort((a,b)=>{{
    let av=a.cells[c]?a.cells[c].textContent.trim().toLowerCase():'';
    let bv=b.cells[c]?b.cells[c].textContent.trim().toLowerCase():'';
    if(c===0){{av=so[av]!==undefined?so[av]:5;bv=so[bv]!==undefined?so[bv]:5;return sortAsc?av-bv:bv-av;}}
    return sortAsc?av.localeCompare(bv):bv.localeCompare(av);
  }});
  rows.forEach(r=>{{tb.appendChild(r);const d=r.nextElementSibling;if(d&&d.classList.contains('detail-row'))tb.appendChild(d);}});
}}
</script>
</body>
</html>"""

    def _render_findings_table(self, findings: List[Finding]) -> str:
        """Render the sortable HTML findings table.

        Args:
            findings: List of Finding objects.

        Returns:
            HTML table string.
        """
        if not findings:
            return '<div class="no-findings"><p>&#x2705; No findings to display.</p></div>'

        rows = []
        for idx, f in enumerate(findings):
            sev = f.severity.lower()
            cat = f.tags[0] if f.tags else "general"
            tags_html = " ".join(f'<span class="tag">{_esc(t)}</span>' for t in f.tags[:5])
            desc = (f.description or "")[:200] + ("..." if len(f.description or "") > 200 else "")
            try:
                detail_json = json.dumps(f.data, indent=2, default=str)[:2000]
            except Exception:
                detail_json = str(f.data)[:2000]
            rows.append(
                f'<tr class="finding-row" data-severity="{_esc(sev)}" onclick="toggleDetail({idx})">'
                f'<td><span class="badge badge-{_esc(sev)}">{_esc(sev)}</span></td>'
                f'<td><div class="finding-title">{_esc(f.title)}</div>'
                f'<div class="finding-desc">{_esc(desc)}</div>'
                f'<div class="finding-tags">{tags_html}</div>'
                f'<div class="finding-details" id="detail-{idx}" style="display:none">{_esc(detail_json)}</div></td>'
                f'<td><span class="tag">{_esc(cat)}</span></td></tr>'
            )
        body = "\n".join(rows)
        return (
            '<div class="findings-table-wrap"><table id="findingsTable">'
            '<thead><tr>'
            '<th data-col="0" onclick="sortTable(0)">Severity <span class="sort-icon">&#x21C5;</span></th>'
            '<th data-col="1" onclick="sortTable(1)">Title / Description <span class="sort-icon">&#x21C5;</span></th>'
            '<th data-col="2" onclick="sortTable(2)">Category <span class="sort-icon">&#x21C5;</span></th>'
            '</tr></thead>'
            f'<tbody id="findingsBody">{body}</tbody>'
            '</table></div>'
        )

    @staticmethod
    def _render_severity_chart(sev_counts: Dict[str, int]) -> str:
        """Render inline SVG severity bar chart.

        Args:
            sev_counts: Dict mapping severity name to count.

        Returns:
            SVG HTML string.
        """
        sevs = ["critical", "high", "medium", "low", "info"]
        colors = {"critical": "#ff3333", "high": "#ff8c00", "medium": "#ffd700", "low": "#4a9eff", "info": "#8b949e"}
        max_val = max(sev_counts.values()) if any(sev_counts.values()) else 1
        bar_h, spacing, label_w, w = 14, 24, 60, 260
        rows = []
        for i, s in enumerate(sevs):
            c = sev_counts.get(s, 0)
            bw = int((c / max_val) * (w - label_w - 36)) if max_val > 0 else 0
            y = i * spacing
            cl = colors[s]
            rows.append(
                f'<text x="0" y="{y+bar_h-2}" font-size="11" fill="#8b949e">{s.capitalize()}</text>'
                f'<rect x="{label_w}" y="{y}" width="{bw}" height="{bar_h}" rx="3" fill="{cl}" opacity="0.85"/>'
                f'<text x="{label_w+bw+5}" y="{y+bar_h-2}" font-size="11" fill="{cl}">{c}</text>'
            )
        h = len(sevs) * spacing + 8
        return f'<svg viewBox="0 0 {w} {h}" width="100%" height="{h}">{"".join(rows)}</svg>'

    @staticmethod
    def _render_category_chart(cat_counts: Dict[str, int]) -> str:
        """Render inline SVG category bar chart.

        Args:
            cat_counts: Dict mapping category label to count.

        Returns:
            SVG HTML string.
        """
        if not cat_counts:
            return '<p style="color:#484f58;font-size:12px">No data.</p>'
        items = sorted(cat_counts.items(), key=lambda x: x[1], reverse=True)[:8]
        max_val = max(v for _, v in items) if items else 1
        bar_h, spacing, label_w, w, color = 14, 24, 70, 260, "#58a6ff"
        rows = []
        for i, (cat, count) in enumerate(items):
            bw = int((count / max_val) * (w - label_w - 36)) if max_val > 0 else 0
            y = i * spacing
            rows.append(
                f'<text x="0" y="{y+bar_h-2}" font-size="11" fill="#8b949e">{_esc(cat[:10])}</text>'
                f'<rect x="{label_w}" y="{y}" width="{bw}" height="{bar_h}" rx="3" fill="{color}" opacity="0.75"/>'
                f'<text x="{label_w+bw+5}" y="{y+bar_h-2}" font-size="11" fill="{color}">{count}</text>'
            )
        h = len(items) * spacing + 8
        return f'<svg viewBox="0 0 {w} {h}" width="100%" height="{h}">{"".join(rows)}</svg>'
