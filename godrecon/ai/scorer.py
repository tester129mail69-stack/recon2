"""Risk scoring engine for GODRECON (stub — Phase 2)."""

from __future__ import annotations

from typing import Dict, List

from godrecon.modules.base import Finding

_SEVERITY_SCORES: Dict[str, int] = {
    "info": 0,
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 100,
}


class RiskScorer:
    """Compute aggregate risk scores for a set of findings.

    Phase 1 stub — applies a simple weighted average of severity scores.
    Phase 2 will incorporate exploit availability, asset criticality, and
    business context.
    """

    def score(self, findings: List[Finding]) -> float:
        """Compute a 0–100 risk score for *findings*.

        Args:
            findings: List of :class:`~godrecon.modules.base.Finding` objects.

        Returns:
            Float risk score between 0 and 100.
        """
        if not findings:
            return 0.0

        total = sum(_SEVERITY_SCORES.get(f.severity, 0) for f in findings)
        return min(100.0, total / len(findings))

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
