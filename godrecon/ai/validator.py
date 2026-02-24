"""False positive validation for GODRECON."""

from __future__ import annotations

import copy
from typing import Any, Dict, List

from godrecon.modules.base import Finding

_LOW_CONFIDENCE_PHRASES = [
    "may be",
    "possibly",
    "potential",
    "could be",
    "might be",
    "suspected",
]

_GENERIC_TITLES = {
    "finding",
    "issue",
    "vulnerability",
    "warning",
    "notice",
    "alert",
}


class FalsePositiveValidator:
    """Heuristic-based false positive filter for scan findings.

    Applies rule-based analysis to remove obvious false positives and
    assign confidence scores to surviving findings.
    """

    def validate(self, findings: List[Finding]) -> List[Finding]:
        """Filter *findings*, removing likely false positives.

        Rules applied:
        - Remove findings with empty title.
        - Remove DNS-only findings without a corresponding HTTP confirmation.
        - Keep all critical findings regardless of other rules.

        Args:
            findings: Raw list of findings from scan modules.

        Returns:
            Filtered list with likely false positives removed.
        """
        # Index HTTP-confirmed findings by target/title similarity
        http_confirmed = {f.title.lower() for f in findings if "http" in f.tags}

        result: List[Finding] = []
        for finding in findings:
            if not finding.title:
                continue
            # Always keep critical findings
            if finding.severity.lower() == "critical":
                result.append(finding)
                continue
            # Filter DNS-only findings that have no HTTP confirmation
            if "dns" in finding.tags and "http" not in finding.tags:
                # Check if a related HTTP finding exists
                title_key = finding.title.lower().replace("dns", "").strip()
                if not any(title_key in h for h in http_confirmed):
                    # Mark lower confidence without mutating the original finding's data
                    f_copy = copy.copy(finding)
                    f_copy.data = dict(finding.data)
                    f_copy.data["_confidence"] = 0.5
                    result.append(f_copy)
                    continue
            result.append(finding)
        return result

    def add_confidence_scores(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Add confidence scores to findings and return as dicts.

        Confidence scoring rules:
        - Critical: 0.95
        - High: 0.85
        - Generic title: -0.2 penalty
        - Low-confidence phrasing in description: -0.1 penalty
        - DNS-only tag: -0.15 penalty
        - Data dict has evidence key: +0.1 bonus

        Args:
            findings: List of :class:`~godrecon.modules.base.Finding` objects.

        Returns:
            List of dicts with all finding fields plus a ``confidence`` key.
        """
        base_scores = {
            "critical": 0.95,
            "high": 0.85,
            "medium": 0.75,
            "low": 0.65,
            "info": 0.55,
        }

        result = []
        for finding in findings:
            confidence = base_scores.get(finding.severity.lower(), 0.6)

            # Penalty: generic title
            if finding.title.lower() in _GENERIC_TITLES:
                confidence -= 0.2

            # Penalty: low-confidence phrasing in description
            desc_lower = finding.description.lower()
            if any(phrase in desc_lower for phrase in _LOW_CONFIDENCE_PHRASES):
                confidence -= 0.1

            # Penalty: DNS-only
            if "dns" in finding.tags and "http" not in finding.tags:
                confidence -= 0.15

            # Bonus: has evidence/data
            if finding.data and len(finding.data) > 1:
                confidence += 0.05

            # Use pre-set confidence if already assigned
            if "_confidence" in finding.data:
                confidence = float(finding.data["_confidence"])

            confidence = round(max(0.0, min(1.0, confidence)), 2)

            result.append({
                "title": finding.title,
                "description": finding.description,
                "severity": finding.severity,
                "data": finding.data,
                "tags": finding.tags,
                "confidence": confidence,
            })

        return result
