"""AI-powered scan analysis — generates summaries, risk assessments, and remediation priorities."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AnalysisReport:
    """Result of an AI-powered scan analysis."""

    executive_summary: str = ""
    risk_score: int = 0
    risk_level: str = "info"
    top_risks: list[dict] = field(default_factory=list)
    remediation_priorities: list[dict] = field(default_factory=list)
    attack_surface_summary: dict = field(default_factory=dict)
    module_summaries: dict[str, str] = field(default_factory=dict)


def _severity_order(sev: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(sev.lower(), 5)


def _risk_level_from_score(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    if score > 0:
        return "low"
    return "info"


class ScanAnalyzer:
    """Generates natural language summaries and risk assessments from scan results.

    Supports two providers:
    - ``"local"`` (default): rule-based analysis, no API key required.
    - ``"openai"``: calls the OpenAI chat completions API, falls back to local on failure.

    Args:
        api_key: API key for the chosen provider (only used when provider is ``"openai"``).
        provider: Analysis backend to use — ``"local"`` or ``"openai"``.
    """

    def __init__(self, api_key: str = "", provider: str = "local") -> None:
        self.api_key = api_key
        self.provider = provider

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, scan_result: dict) -> AnalysisReport:
        """Analyse *scan_result* and return an :class:`AnalysisReport`.

        If the provider is ``"openai"`` and the API call fails, this method
        falls back transparently to the local rule-based provider.

        Args:
            scan_result: Dictionary produced by the scan engine.

        Returns:
            Populated :class:`AnalysisReport` instance.
        """
        if self.provider == "openai" and self.api_key:
            try:
                import asyncio

                return asyncio.run(self._analyze_openai(scan_result))
            except Exception:  # noqa: BLE001
                pass
        return self._analyze_local(scan_result)

    # ------------------------------------------------------------------
    # Local (rule-based) provider
    # ------------------------------------------------------------------

    def _analyze_local(self, scan_result: dict) -> AnalysisReport:
        target = scan_result.get("target", "unknown")
        module_results: dict[str, Any] = scan_result.get("module_results", {})

        # Collect all findings across modules
        all_findings: list[dict] = []
        for mod_result in module_results.values():
            if mod_result is None:
                continue
            findings = []
            if hasattr(mod_result, "findings"):
                findings = mod_result.findings
            elif isinstance(mod_result, dict):
                findings = mod_result.get("findings", [])
            for f in findings:
                if isinstance(f, dict):
                    all_findings.append(f)
                elif hasattr(f, "__dict__"):
                    all_findings.append(
                        {
                            "title": getattr(f, "title", ""),
                            "description": getattr(f, "description", ""),
                            "severity": getattr(f, "severity", "info"),
                            "data": getattr(f, "data", {}),
                            "tags": getattr(f, "tags", []),
                        }
                    )

        # Count by severity
        sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in all_findings:
            sev = (f.get("severity") or "info").lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        # Risk score (capped at 100)
        raw_score = (
            sev_counts["critical"] * 25 + sev_counts["high"] * 15 + sev_counts["medium"] * 5 + sev_counts["low"] * 1
        )
        risk_score = min(raw_score, 100)
        risk_level = _risk_level_from_score(risk_score)

        modules_run = list(module_results.keys())
        total = len(all_findings)
        executive_summary = (
            f"Scan of {target} completed with {total} findings across "
            f"{len(modules_run)} modules. "
            f"{sev_counts['critical']} critical and {sev_counts['high']} high severity "
            f"issues require immediate attention. "
            f"The overall risk level is {risk_level}."
        )

        # Top 5 risks — highest severity first
        sorted_findings = sorted(all_findings, key=lambda f: _severity_order(f.get("severity", "info")))
        top_risks = [
            {
                "title": f.get("title", ""),
                "severity": f.get("severity", "info"),
                "description": f.get("description", ""),
                "explanation": (
                    f"This {f.get('severity', 'info')}-severity finding may indicate "
                    "a security weakness that should be investigated."
                ),
            }
            for f in sorted_findings[:5]
        ]

        # Remediation priorities — same ordering
        remediation_priorities = [
            {
                "priority": idx + 1,
                "title": f.get("title", ""),
                "severity": f.get("severity", "info"),
                "recommended_action": (
                    f"Investigate and remediate the {f.get('severity', 'info')}-severity finding: {f.get('title', '')}."
                ),
            }
            for idx, f in enumerate(sorted_findings[:10])
        ]

        # Attack surface summary
        attack_surface_summary = {
            "subdomains": _count_module_findings(module_results, "subdomains"),
            "open_ports": _count_module_findings(module_results, "ports"),
            "vulnerabilities_by_severity": sev_counts,
            "total_findings": total,
            "modules_run": len(modules_run),
        }

        # Per-module summaries
        module_summaries: dict[str, str] = {}
        for mod_name, mod_result in module_results.items():
            if mod_result is None:
                module_summaries[mod_name] = f"{mod_name} did not return results."
                continue
            findings = []
            if hasattr(mod_result, "findings"):
                findings = mod_result.findings
            elif isinstance(mod_result, dict):
                findings = mod_result.get("findings", [])

            count = len(findings)
            sev_breakdown: dict[str, int] = {}
            for f in findings:
                sev = ""
                if isinstance(f, dict):
                    sev = (f.get("severity") or "info").lower()
                elif hasattr(f, "severity"):
                    sev = (f.severity or "info").lower()
                sev_breakdown[sev] = sev_breakdown.get(sev, 0) + 1

            breakdown_str = ", ".join(f"{v} {k}" for k, v in sev_breakdown.items()) or "none"
            module_summaries[mod_name] = f"{mod_name} discovered {count} findings ({breakdown_str})."

        return AnalysisReport(
            executive_summary=executive_summary,
            risk_score=risk_score,
            risk_level=risk_level,
            top_risks=top_risks,
            remediation_priorities=remediation_priorities,
            attack_surface_summary=attack_surface_summary,
            module_summaries=module_summaries,
        )

    # ------------------------------------------------------------------
    # OpenAI provider
    # ------------------------------------------------------------------

    async def _analyze_openai(self, scan_result: dict) -> AnalysisReport:
        """Call the OpenAI chat completions API and parse the response.

        Falls back to :meth:`_analyze_local` on any error.
        """
        import json

        import aiohttp

        prompt = (
            "You are a cybersecurity expert. Analyse the following reconnaissance scan "
            "results and return a JSON object with keys: executive_summary (string), "
            "risk_score (0-100 int), risk_level (string), top_risks (list of dicts with "
            "title/severity/description/explanation), remediation_priorities (list of dicts "
            "with priority/title/severity/recommended_action), attack_surface_summary (dict), "
            "module_summaries (dict mapping module name to summary string).\n\n"
            f"Scan results:\n{json.dumps(scan_result, default=str)[:8000]}"
        )

        payload = {
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": prompt}],
            "response_format": {"type": "json_object"},
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        async with (
            aiohttp.ClientSession() as session,
            session.post(
                "https://api.openai.com/v1/chat/completions",
                json=payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp,
        ):
            resp.raise_for_status()
            data = await resp.json()

        content = data["choices"][0]["message"]["content"]
        parsed = json.loads(content)
        return AnalysisReport(
            executive_summary=parsed.get("executive_summary", ""),
            risk_score=int(parsed.get("risk_score", 0)),
            risk_level=parsed.get("risk_level", "info"),
            top_risks=parsed.get("top_risks", []),
            remediation_priorities=parsed.get("remediation_priorities", []),
            attack_surface_summary=parsed.get("attack_surface_summary", {}),
            module_summaries=parsed.get("module_summaries", {}),
        )


def _count_module_findings(module_results: dict, module_name: str) -> int:
    """Return the number of findings for *module_name*, or 0."""
    mr = module_results.get(module_name)
    if mr is None:
        return 0
    if hasattr(mr, "findings"):
        return len(mr.findings)
    if isinstance(mr, dict):
        return len(mr.get("findings", []))
    return 0
