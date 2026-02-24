"""Risk scoring engine for GODRECON."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List

from godrecon.modules.base import Finding

_SEVERITY_SCORES: Dict[str, int] = {
    "info": 0,
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 100,
}

# Category-based weight multipliers
_MAX_CATEGORY_WEIGHT: float = 1.5

_CATEGORY_WEIGHTS: Dict[str, float] = {
    "secrets": _MAX_CATEGORY_WEIGHT,
    "misconfig": 1.2,
    "cloud": 1.3,
    "api": 1.1,
    "crawl": 1.0,
    "osint": 0.8,
    "tech": 0.7,
    "dns": 0.9,
    "ssl": 1.0,
    "vuln": 1.4,
}


class RiskScorer:
    """Compute aggregate risk scores for a set of findings.

    Uses a weighted algorithm that amplifies critical findings and applies
    category-specific multipliers to compute a 0–100 risk score.
    """

    def score(self, findings: List[Finding]) -> float:
        """Compute a 0–100 risk score for *findings*.

        Critical findings have a disproportionate impact on the score.
        The formula uses a weighted sum normalised by the maximum possible
        score, then scaled to 100.

        Args:
            findings: List of :class:`~godrecon.modules.base.Finding` objects.

        Returns:
            Float risk score between 0.0 and 100.0.
        """
        if not findings:
            return 0.0

        weighted_total = 0.0
        for finding in findings:
            base = _SEVERITY_SCORES.get(finding.severity.lower(), 0)
            # Apply category weight from tags
            multiplier = 1.0
            for tag in finding.tags:
                if tag in _CATEGORY_WEIGHTS:
                    multiplier = max(multiplier, _CATEGORY_WEIGHTS[tag])
            weighted_total += base * multiplier

        # Critical findings add bonus points to push score higher
        critical_count = sum(1 for f in findings if f.severity.lower() == "critical")
        critical_bonus = min(25.0, critical_count * 5.0)

        max_possible = len(findings) * 100 * max(_CATEGORY_WEIGHTS.values(), default=_MAX_CATEGORY_WEIGHT)  # max weighted score per finding
        raw_score = (weighted_total / max_possible) * 100 + critical_bonus
        return round(min(100.0, raw_score), 1)

    def score_by_severity(self, findings: List[Finding]) -> Dict[str, int]:
        """Return a count of findings grouped by severity level.

        Args:
            findings: List of :class:`~godrecon.modules.base.Finding` objects.

        Returns:
            Dict mapping severity string to count.
        """
        counts: Dict[str, int] = {s: 0 for s in _SEVERITY_SCORES}
        for finding in findings:
            severity = finding.severity.lower()
            if severity in counts:
                counts[severity] += 1
        return counts

    def risk_breakdown(self, findings: List[Finding]) -> Dict[str, Any]:
        """Return detailed risk breakdown with per-category scores.

        Args:
            findings: List of :class:`~godrecon.modules.base.Finding` objects.

        Returns:
            Dict with overall_score, severity_counts, category_scores, top_findings.
        """
        severity_counts = self.score_by_severity(findings)
        overall = self.score(findings)

        # Group by category (using first matching tag as category)
        category_findings: Dict[str, List[Finding]] = defaultdict(list)
        for finding in findings:
            cat = "general"
            for tag in finding.tags:
                if tag not in {"info", "low", "medium", "high", "critical"}:
                    cat = tag
                    break
            category_findings[cat].append(finding)

        category_scores: Dict[str, float] = {
            cat: self.score(cat_findings)
            for cat, cat_findings in category_findings.items()
        }

        top_findings = sorted(
            findings,
            key=lambda f: _SEVERITY_SCORES.get(f.severity.lower(), 0),
            reverse=True,
        )[:5]

        return {
            "overall_score": overall,
            "severity_counts": severity_counts,
            "category_scores": category_scores,
            "top_findings": [
                {"title": f.title, "severity": f.severity} for f in top_findings
            ],
            "total_findings": len(findings),
        }

    def executive_summary(self, findings: List[Finding], target: str) -> str:
        """Generate an executive summary paragraph based on findings.

        Args:
            findings: List of :class:`~godrecon.modules.base.Finding` objects.
            target: Scan target string.

        Returns:
            Formatted executive summary text.
        """
        score = self.score(findings)
        counts = self.score_by_severity(findings)
        total = len(findings)

        if score >= 80:
            risk_label = "CRITICAL"
            risk_desc = (
                "The target presents severe security risks that require immediate remediation. "
                "Critical and high-severity vulnerabilities were identified that may allow "
                "unauthorised access, data exfiltration, or system compromise."
            )
        elif score >= 60:
            risk_label = "HIGH"
            risk_desc = (
                "Significant security issues were identified. High-priority remediation "
                "is recommended to reduce exposure and prevent potential exploitation."
            )
        elif score >= 40:
            risk_label = "MEDIUM"
            risk_desc = (
                "Multiple medium-severity issues were identified alongside some higher-risk "
                "findings. A structured remediation plan should be implemented."
            )
        elif score >= 20:
            risk_label = "LOW"
            risk_desc = (
                "The target demonstrates a reasonable security posture with some low to "
                "medium-severity issues that should be addressed as part of regular maintenance."
            )
        else:
            risk_label = "INFORMATIONAL"
            risk_desc = (
                "No critical security issues were identified. The findings are primarily "
                "informational and represent opportunities for incremental security improvement."
            )

        severity_summary = ", ".join(
            f"{v} {k}" for k, v in counts.items() if v > 0
        )

        return (
            f"GODRECON Security Assessment — {target}\n\n"
            f"Overall Risk Score: {score:.0f}/100 ({risk_label})\n\n"
            f"{risk_desc}\n\n"
            f"Total findings: {total} ({severity_summary}).\n"
        )
