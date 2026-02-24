"""Technology fingerprinting for GODRECON.

Provides :class:`TechFingerprinter` which identifies web technologies from
HTTP response headers, body patterns, cookies, meta tags, and script tags by
matching against the fingerprints database.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_FINGERPRINTS_PATH = Path(__file__).parent.parent.parent / "data" / "fingerprints.json"


def _load_fingerprints() -> List[Dict[str, Any]]:
    """Load the fingerprints database from disk.

    Returns:
        List of fingerprint dicts.
    """
    try:
        with _FINGERPRINTS_PATH.open("r") as fh:
            data = json.load(fh)
            return data.get("fingerprints", [])
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to load fingerprints database: %s", exc)
        return []


_FINGERPRINTS: List[Dict[str, Any]] = _load_fingerprints()


class TechFingerprinter:
    """Identify technologies from HTTP response data.

    Matches the provided response against the fingerprints database using
    header patterns, cookie patterns, body patterns, meta tag patterns, and
    script patterns.

    Args:
        headers: Response headers dict (lowercase keys).
        body: Response body string.
        cookies: Cookie string from Set-Cookie header.
        url: The response URL (for context).
    """

    def __init__(
        self,
        headers: Dict[str, str],
        body: str = "",
        cookies: str = "",
        url: str = "",
    ) -> None:
        self._headers = {k.lower(): v for k, v in headers.items()}
        self._body = body
        self._cookies = cookies
        self._url = url
        # Combine headers as a single string for easier pattern matching
        self._headers_str = " ".join(f"{k}: {v}" for k, v in self._headers.items())

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fingerprint(self) -> List[Dict[str, Any]]:
        """Run all fingerprint checks and return detected technologies.

        Returns:
            List of dicts with keys ``name``, ``category``, ``version``,
            ``website``, and ``confidence``.
        """
        detected: Dict[str, Dict[str, Any]] = {}

        for fp in _FINGERPRINTS:
            name = fp.get("name", "")
            if not name:
                continue
            confidence = 0
            version = ""

            # Header patterns
            for pat in fp.get("header_patterns", []):
                try:
                    if re.search(pat, self._headers_str, re.IGNORECASE):
                        confidence += 40
                        # Try version extraction
                        if fp.get("version_regex"):
                            m = re.search(fp["version_regex"], self._headers_str, re.IGNORECASE)
                            if m:
                                version = m.group(1)
                        break
                except re.error:
                    pass

            # Cookie patterns
            for pat in fp.get("cookie_patterns", []):
                try:
                    if re.search(pat, self._cookies, re.IGNORECASE):
                        confidence += 30
                        break
                except re.error:
                    pass

            # Body patterns
            for pat in fp.get("body_patterns", []):
                try:
                    if re.search(pat, self._body, re.IGNORECASE):
                        confidence += 30
                        if fp.get("version_regex") and not version:
                            m = re.search(fp["version_regex"], self._body, re.IGNORECASE)
                            if m:
                                version = m.group(1)
                        break
                except re.error:
                    pass

            # Meta tag patterns
            for pat in fp.get("meta_patterns", []):
                try:
                    if re.search(pat, self._body, re.IGNORECASE):
                        confidence += 35
                        if fp.get("version_regex") and not version:
                            m = re.search(fp["version_regex"], self._body, re.IGNORECASE)
                            if m:
                                version = m.group(1)
                        break
                except re.error:
                    pass

            # Script patterns
            for pat in fp.get("script_patterns", []):
                try:
                    if re.search(pat, self._body, re.IGNORECASE):
                        confidence += 25
                        if fp.get("version_regex") and not version:
                            m = re.search(fp["version_regex"], self._body, re.IGNORECASE)
                            if m:
                                version = m.group(1)
                        break
                except re.error:
                    pass

            # URL patterns
            for pat in fp.get("url_patterns", []):
                try:
                    if re.search(pat, self._url, re.IGNORECASE):
                        confidence += 20
                        break
                except re.error:
                    pass

            if confidence >= 20:
                if name not in detected or detected[name]["confidence"] < confidence:
                    detected[name] = {
                        "name": name,
                        "category": fp.get("category", "unknown"),
                        "version": version,
                        "website": fp.get("website", ""),
                        "confidence": min(confidence, 100),
                    }

        return sorted(detected.values(), key=lambda x: -x["confidence"])
