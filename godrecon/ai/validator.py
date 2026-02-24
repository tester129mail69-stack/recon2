"""ML-based false positive filter for GODRECON (stub — Phase 2)."""

from __future__ import annotations

from typing import List

from godrecon.modules.base import Finding


class FalsePositiveValidator:
    """ML-based validator that filters false positive findings.

    This is a Phase 1 stub. Phase 2 will integrate a trained classifier.
    Currently applies heuristic rules only.
    """

    def validate(self, findings: List[Finding]) -> List[Finding]:
        """Filter *findings*, removing likely false positives.

        Args:
            findings: Raw list of findings from scan modules.

        Returns:
            Filtered list with likely false positives removed.
        """
        return [f for f in findings if self._is_valid(f)]

    @staticmethod
    def _is_valid(finding: Finding) -> bool:
        """Apply heuristic rules to determine if *finding* is likely valid."""
        # Suppress findings without a title
        if not finding.title:
            return False
        return True
