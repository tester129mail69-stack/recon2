"""Security posture scoring for GODRECON.

Aggregates findings from all scan modules, scores 7 security categories,
generates a letter grade, and provides remediation recommendations.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# Category weights (must sum to 100)
_CATEGORY_WEIGHTS: Dict[str, int] = {
    "network": 15,
    "web": 20,
    "dns": 10,
    "ssl_tls": 15,
    "cloud": 10,
    "application": 20,
    "information_exposure": 10,
}

# Severity penalty points per finding
_SEVERITY_PENALTY: Dict[str, int] = {
    "critical": 30,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 0,
}

# Map module names to categories
_MODULE_TO_CATEGORY: Dict[str, str] = {
    "ports": "network",
    "http": "web",
    "ssl": "ssl_tls",
    "dns": "dns",
    "email_sec": "dns",
    "cloud": "cloud",
    "tech": "application",
    "vulns": "application",
    "subdomains": "information_exposure",
    "osint": "information_exposure",
    "takeover": "dns",
    "content_discovery": "information_exposure",
    "api_intel": "application",
    "crawl": "application",
    "screenshots": "information_exposure",
}

# Letter grade thresholds
_GRADE_THRESHOLDS: List[Tuple[int, str]] = [
    (97, "A+"),
    (93, "A"),
    (90, "A-"),
    (87, "B+"),
    (83, "B"),
    (80, "B-"),
    (77, "C+"),
    (73, "C"),
    (70, "C-"),
    (67, "D+"),
    (63, "D"),
    (60, "D-"),
    (0, "F"),
]


class SecurityPostureScorer:
    """Aggregate module findings into a security posture score and grade.

    Args:
        module_results: Dict mapping module name to
            :class:`~godrecon.modules.base.ModuleResult` objects (or their
            serialised ``raw`` dicts) from the scan.
    """

    def __init__(self, module_results: Dict[str, Any]) -> None:
        self._results = module_results

    def score(self) -> Dict[str, Any]:
        """Calculate the overall security posture score.

        Returns:
            Dict with keys:
            - ``overall_score`` (int 0–100)
            - ``grade`` (str, e.g. ``"B+"``),
            - ``categories`` (dict of category scores),
            - ``recommendations`` (list of recommendation strings),
            - ``summary`` (str)
        """
        category_penalties: Dict[str, int] = {k: 0 for k in _CATEGORY_WEIGHTS}
        category_findings: Dict[str, List[Dict[str, Any]]] = {k: [] for k in _CATEGORY_WEIGHTS}

        for module_name, module_result in self._results.items():
            category = _MODULE_TO_CATEGORY.get(module_name, "application")
            findings = self._extract_findings(module_result)
            for finding in findings:
                sev = finding.get("severity", "info")
                penalty = _SEVERITY_PENALTY.get(sev, 0)
                category_penalties[category] += penalty
                category_findings[category].append(finding)

        # Score each category (100 - capped penalty)
        category_scores: Dict[str, int] = {}
        for cat in _CATEGORY_WEIGHTS:
            penalty = min(category_penalties.get(cat, 0), 100)
            category_scores[cat] = max(0, 100 - penalty)

        # Weighted overall score
        overall = 0
        for cat, weight in _CATEGORY_WEIGHTS.items():
            overall += int(category_scores[cat] * weight / 100)

        grade = _score_to_grade(overall)
        recommendations = self._generate_recommendations(category_findings, category_scores)

        summary = (
            f"Overall security score: {overall}/100 (Grade {grade}). "
            + self._build_summary_text(overall, category_scores)
        )

        return {
            "overall_score": overall,
            "grade": grade,
            "categories": {
                cat: {
                    "score": category_scores[cat],
                    "findings_count": len(category_findings.get(cat, [])),
                }
                for cat in _CATEGORY_WEIGHTS
            },
            "recommendations": recommendations,
            "summary": summary,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_findings(module_result: Any) -> List[Dict[str, Any]]:
        """Extract a list of finding-like dicts from a module result.

        Handles both :class:`~godrecon.modules.base.ModuleResult` dataclass
        instances and plain dicts.

        Args:
            module_result: Module result object or serialised dict.

        Returns:
            List of finding dicts with at least a ``severity`` key.
        """
        # ModuleResult dataclass
        if hasattr(module_result, "findings"):
            findings = module_result.findings or []
            return [
                {
                    "title": getattr(f, "title", ""),
                    "severity": getattr(f, "severity", "info"),
                    "tags": getattr(f, "tags", []),
                }
                for f in findings
            ]
        # Plain dict (already serialised)
        if isinstance(module_result, dict):
            return module_result.get("findings", [])
        return []

    @staticmethod
    def _generate_recommendations(
        category_findings: Dict[str, List[Dict[str, Any]]],
        category_scores: Dict[str, int],
    ) -> List[Dict[str, Any]]:
        """Generate remediation recommendations for low-scoring categories.

        Args:
            category_findings: Map of category to its findings list.
            category_scores: Map of category to its score.

        Returns:
            List of recommendation dicts with ``category``, ``score``,
            ``priority``, and ``advice`` keys.
        """
        recs: List[Dict[str, Any]] = []

        _advice = {
            "network": (
                "Restrict exposed network services. Close unnecessary ports, "
                "apply firewall rules, and avoid exposing management interfaces publicly."
            ),
            "web": (
                "Harden web services: add missing security headers (HSTS, CSP, "
                "X-Frame-Options), fix CORS misconfigurations, and update web frameworks."
            ),
            "dns": (
                "Improve DNS security: enable DNSSEC, configure SPF/DMARC/DKIM "
                "records, remove dangling CNAME entries."
            ),
            "ssl_tls": (
                "Strengthen TLS configuration: disable old protocols (TLSv1.0/1.1), "
                "remove weak cipher suites, and renew expiring certificates."
            ),
            "cloud": (
                "Audit cloud storage: ensure S3 buckets, Azure blobs, and GCS "
                "buckets are not publicly accessible unless intentional."
            ),
            "application": (
                "Patch known CVEs in detected technologies, disable debug modes, "
                "remove default credentials, and protect admin panels."
            ),
            "information_exposure": (
                "Remove exposed sensitive files (.git, .env, backup files), "
                "disable directory listing, and restrict access to internal paths."
            ),
        }

        for cat, score in sorted(category_scores.items(), key=lambda x: x[1]):
            if score >= 90:
                continue
            critical_count = sum(
                1 for f in category_findings.get(cat, []) if f.get("severity") == "critical"
            )
            high_count = sum(
                1 for f in category_findings.get(cat, []) if f.get("severity") == "high"
            )
            if score < 60:
                priority = "critical"
            elif score < 75:
                priority = "high"
            elif score < 85:
                priority = "medium"
            else:
                priority = "low"

            recs.append({
                "category": cat,
                "score": score,
                "priority": priority,
                "critical_findings": critical_count,
                "high_findings": high_count,
                "advice": _advice.get(cat, "Review and remediate findings in this category."),
            })

        return recs

    @staticmethod
    def _build_summary_text(
        overall: int, category_scores: Dict[str, int]
    ) -> str:
        """Build a human-readable summary of weak categories.

        Args:
            overall: Overall score.
            category_scores: Per-category scores.

        Returns:
            Summary string.
        """
        weak = [cat for cat, sc in category_scores.items() if sc < 70]
        if not weak:
            return "All security categories are in good shape."
        categories_str = ", ".join(w.replace("_", " ").title() for w in weak)
        return f"Weakest categories requiring attention: {categories_str}."


def _score_to_grade(score: int) -> str:
    """Convert a numeric score to a letter grade.

    Args:
        score: Numeric score 0–100.

    Returns:
        Letter grade string (``"A+"`` through ``"F"``).
    """
    for threshold, grade in _GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"
