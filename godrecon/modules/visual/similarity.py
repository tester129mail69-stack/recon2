"""Visual similarity analysis for GODRECON.

Compares screenshots using perceptual hashing (average hash / difference hash)
powered by Pillow.  Groups similar-looking pages and detects default/parking
pages, login pages, error pages, and admin panels.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Optional Pillow import
# ---------------------------------------------------------------------------
try:
    from PIL import Image  # type: ignore[import]
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False


# ---------------------------------------------------------------------------
# Page-type detection patterns
# ---------------------------------------------------------------------------

_LOGIN_PATTERNS: List[str] = [
    r"<input[^>]+type=[\"']password[\"']",
    r"<form[^>]*login",
    r"sign[\s_-]*in",
    r"log[\s_-]*in",
    r"username.*password",
]

_ADMIN_PATTERNS: List[str] = [
    r"/admin",
    r"admin\s*panel",
    r"administration",
    r"dashboard",
    r"phpMyAdmin",
    r"wp-admin",
    r"control[\s_-]*panel",
]

_DEFAULT_PAGE_PATTERNS: List[str] = [
    r"welcome to nginx",
    r"apache2 ubuntu default page",
    r"iis windows server",
    r"it works!",
    r"test page for the apache",
    r"default web site page",
    r"parking page",
    r"domain for sale",
    r"this site is coming soon",
    r"under construction",
]

_ERROR_PAGE_PATTERNS: List[str] = [
    r"<title>[^<]*(404|403|500|502|503)[^<]*</title>",
    r"not found",
    r"forbidden",
    r"internal server error",
    r"bad gateway",
    r"service unavailable",
    r"traceback \(most recent call last\)",
    r"stack trace",
    r"exception in",
]


class PageClassification:
    """Classification result for a single page.

    Attributes:
        url: URL of the page.
        page_type: Detected type (``login``, ``admin``, ``default``, ``error``, ``custom``).
        severity: Severity level for reporting.
        patterns_matched: Which detection patterns fired.
        hash_value: Perceptual hash string (if Pillow available).
    """

    def __init__(self, url: str) -> None:
        self.url = url
        self.page_type: str = "custom"
        self.severity: str = "info"
        self.patterns_matched: List[str] = []
        self.hash_value: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain dictionary."""
        return {
            "url": self.url,
            "page_type": self.page_type,
            "severity": self.severity,
            "patterns_matched": self.patterns_matched,
            "hash_value": self.hash_value,
        }


class SimilarityGroup:
    """A group of visually similar pages.

    Attributes:
        representative_url: URL of the canonical member.
        members: List of URLs in this group.
        hash_value: Perceptual hash of the representative image.
    """

    def __init__(self, representative_url: str, hash_value: Optional[str] = None) -> None:
        self.representative_url = representative_url
        self.members: List[str] = [representative_url]
        self.hash_value = hash_value

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain dictionary."""
        return {
            "representative_url": self.representative_url,
            "member_count": len(self.members),
            "members": self.members,
            "hash_value": self.hash_value,
        }


class VisualSimilarityAnalyzer:
    """Analyse visual similarity and classify page types.

    Args:
        similarity_threshold: Maximum Hamming distance to treat two hashes
                              as "similar" (default 10 out of 64 bits).
    """

    def __init__(self, similarity_threshold: int = 10) -> None:
        self.similarity_threshold = similarity_threshold

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def classify_page(
        self,
        url: str,
        html_content: Optional[str] = None,
        screenshot_path: Optional[str] = None,
    ) -> PageClassification:
        """Classify a single page based on content and screenshot.

        Args:
            url: Page URL.
            html_content: Raw HTML body, if available.
            screenshot_path: Path to screenshot PNG, if available.

        Returns:
            :class:`PageClassification` for this page.
        """
        classification = PageClassification(url)

        # Compute perceptual hash from screenshot
        if screenshot_path and PILLOW_AVAILABLE:
            classification.hash_value = self._compute_phash(screenshot_path)

        if html_content:
            lower = html_content.lower()

            # Check for login pages
            for pattern in _LOGIN_PATTERNS:
                if re.search(pattern, lower, re.IGNORECASE):
                    classification.page_type = "login"
                    classification.severity = "info"
                    classification.patterns_matched.append(pattern)
                    break

            # Check for admin panels (can override login)
            for pattern in _ADMIN_PATTERNS:
                if re.search(pattern, lower, re.IGNORECASE):
                    classification.page_type = "admin"
                    classification.severity = "medium"
                    classification.patterns_matched.append(pattern)
                    break

            # Check for default/parking pages
            if classification.page_type == "custom":
                for pattern in _DEFAULT_PAGE_PATTERNS:
                    if re.search(pattern, lower, re.IGNORECASE):
                        classification.page_type = "default"
                        classification.severity = "low"
                        classification.patterns_matched.append(pattern)
                        break

            # Check for error pages (with stack traces → medium severity)
            if classification.page_type == "custom":
                for pattern in _ERROR_PAGE_PATTERNS:
                    if re.search(pattern, lower, re.IGNORECASE):
                        classification.page_type = "error"
                        if re.search(r"traceback|stack trace|exception in", lower):
                            classification.severity = "medium"
                        else:
                            classification.severity = "info"
                        classification.patterns_matched.append(pattern)
                        break

        return classification

    def group_similar(
        self,
        screenshot_paths: Dict[str, str],
    ) -> List[SimilarityGroup]:
        """Group URLs by visually similar screenshots.

        Args:
            screenshot_paths: Mapping of URL → screenshot file path.

        Returns:
            List of :class:`SimilarityGroup` objects.
        """
        if not PILLOW_AVAILABLE:
            logger.warning(
                "Pillow not installed — skipping visual similarity grouping. "
                "Install with: pip install Pillow"
            )
            return []

        # Build (url, hash) pairs
        url_hashes: List[Tuple[str, str]] = []
        for url, path in screenshot_paths.items():
            h = self._compute_phash(path)
            if h:
                url_hashes.append((url, h))

        groups: List[SimilarityGroup] = []
        assigned: set = set()

        for i, (url_i, hash_i) in enumerate(url_hashes):
            if url_i in assigned:
                continue
            group = SimilarityGroup(representative_url=url_i, hash_value=hash_i)
            assigned.add(url_i)

            for url_j, hash_j in url_hashes[i + 1:]:
                if url_j in assigned:
                    continue
                if self._hamming_distance(hash_i, hash_j) <= self.similarity_threshold:
                    group.members.append(url_j)
                    assigned.add(url_j)

            groups.append(group)

        return groups

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_phash(path: str) -> Optional[str]:
        """Compute a perceptual hash string for an image file.

        Args:
            path: Path to the PNG/JPEG file.

        Returns:
            Hex string hash, or ``None`` on error.
        """
        if not PILLOW_AVAILABLE:
            return None
        try:
            with Image.open(path) as img:
                img = img.convert("L").resize((8, 8), Image.LANCZOS)
                pixels = list(img.getdata())
                avg = sum(pixels) / len(pixels)
                bits = "".join("1" if p >= avg else "0" for p in pixels)
                return hex(int(bits, 2))[2:].zfill(16)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Could not compute hash for %s: %s", path, exc)
            return None

    @staticmethod
    def _hamming_distance(hash_a: str, hash_b: str) -> int:
        """Compute the bit-level Hamming distance between two hex hash strings.

        Args:
            hash_a: First hash (hex string).
            hash_b: Second hash (hex string).

        Returns:
            Number of differing bits (0 = identical).
        """
        try:
            int_a = int(hash_a, 16)
            int_b = int(hash_b, 16)
            return bin(int_a ^ int_b).count("1")
        except ValueError:
            return 64  # treat incomparable hashes as maximally different
