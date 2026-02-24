"""JavaScript secret scanner for GODRECON."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_DATA_DIR = Path(__file__).parent.parent.parent / "data"


def _load_patterns() -> List[Dict[str, Any]]:
    """Load JS secret patterns from bundled JSON file.

    Returns:
        List of pattern dicts.
    """
    path = _DATA_DIR / "js_patterns.json"
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to load js_patterns.json: %s", exc)
    return []


def _redact(value: str) -> str:
    """Redact the middle portion of a matched secret.

    Shows first 4 and last 4 characters only.

    Args:
        value: Full matched string.

    Returns:
        Redacted representation.
    """
    if len(value) <= 10:
        return "****"
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


class JSAnalyzer:
    """Scan JavaScript files for exposed secrets and sensitive data."""

    def __init__(self) -> None:
        """Initialise and load secret patterns."""
        self._patterns = _load_patterns()

    async def analyze(self, js_url: str, http: AsyncHTTPClient) -> List[Dict[str, Any]]:
        """Analyse a JavaScript file at *js_url* for secrets.

        Args:
            js_url: URL of the JS file to analyse.
            http: Shared async HTTP client.

        Returns:
            List of finding dicts with: pattern_name, match, line, severity, url.
        """
        findings: List[Dict[str, Any]] = []
        try:
            resp = await http.get(js_url)
            if not resp or resp.get("status") != 200:
                return findings
            body = resp.get("body", "")
            if not body:
                return findings
        except Exception as exc:  # noqa: BLE001
            logger.debug("JS fetch failed for %s: %s", js_url, exc)
            return findings

        lines = body.splitlines()
        for pattern_def in self._patterns:
            pattern_name = pattern_def.get("name", "Unknown")
            regex_str = pattern_def.get("pattern", "")
            severity = pattern_def.get("severity", "medium")
            description = pattern_def.get("description", "")
            if not regex_str:
                continue
            try:
                compiled = re.compile(regex_str, re.MULTILINE)
            except re.error as exc:
                logger.debug("Bad regex pattern '%s': %s", pattern_name, exc)
                continue

            for lineno, line in enumerate(lines, start=1):
                for match in compiled.finditer(line):
                    matched_val = match.group(0)
                    findings.append({
                        "pattern_name": pattern_name,
                        "match": _redact(matched_val),
                        "line": lineno,
                        "severity": severity,
                        "url": js_url,
                        "description": description,
                    })

        return findings
