"""Google dork generator for GODRECON OSINT."""

from __future__ import annotations

import json
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List

from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_DATA_DIR = Path(__file__).parent.parent.parent / "data"


def _load_dork_templates() -> List[Dict[str, Any]]:
    """Load dork templates from the bundled JSON data file.

    Returns:
        List of dork template dicts.
    """
    path = _DATA_DIR / "dork_templates.json"
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to load dork templates: %s", exc)
    return []


class GoogleDorkScanner:
    """Generate and catalogue Google dork queries for a target."""

    def __init__(self) -> None:
        """Initialise the scanner and load templates."""
        self._templates: List[Dict[str, Any]] = _load_dork_templates()

    async def generate_dorks(self, target: str) -> List[Dict[str, Any]]:
        """Generate dork queries for *target*.

        Does not execute searches (avoids rate limiting / CAPTCHAs).
        Returns query URLs only.

        Args:
            target: Domain name of the target (e.g., ``example.com``).

        Returns:
            List of dicts with keys: name, dork, url, category, severity.
        """
        results: List[Dict[str, Any]] = []
        for template in self._templates:
            dork = template.get("dork", "").replace("{target}", target)
            encoded = urllib.parse.quote_plus(dork)
            google_url = f"https://www.google.com/search?q={encoded}"
            results.append(
                {
                    "name": template.get("name", ""),
                    "dork": dork,
                    "url": google_url,
                    "category": template.get("category", "general"),
                    "severity": template.get("severity", "info"),
                }
            )
        return results
