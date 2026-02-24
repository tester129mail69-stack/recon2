"""Nuclei-style pattern matching vulnerability detection engine for GODRECON.

Loads vulnerability templates from ``godrecon/data/vuln_templates.json`` and
runs concurrent HTTP checks against the scan target using
:class:`~godrecon.utils.http_client.AsyncHTTPClient`.
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_DATA_DIR = Path(__file__).parent.parent.parent / "data"
_TEMPLATES_JSON = _DATA_DIR / "vuln_templates.json"

_DEFAULT_CONCURRENCY = 20
_DEFAULT_TIMEOUT = 10


def _load_templates() -> List[Dict[str, Any]]:
    """Load vulnerability templates from the JSON data file.

    Returns:
        List of template dicts.
    """
    try:
        with _TEMPLATES_JSON.open("r") as fh:
            return json.load(fh)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to load vuln templates: %s", exc)
        return []


class PatternMatcher:
    """Nuclei-style vulnerability detection engine.

    Loads templates and runs them concurrently against a target URL using
    the shared HTTP client.  Operates in *safe mode* by default — no
    destructive payloads are executed.

    Args:
        http_client: Shared :class:`~godrecon.utils.http_client.AsyncHTTPClient`.
        concurrency: Maximum concurrent template checks.
        safe_mode: When ``True``, skip any templates flagged as destructive.
        severity_threshold: Minimum severity to run (``info``, ``low``,
                            ``medium``, ``high``, ``critical``).
    """

    _SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

    def __init__(
        self,
        http_client: AsyncHTTPClient,
        concurrency: int = _DEFAULT_CONCURRENCY,
        safe_mode: bool = True,
        severity_threshold: str = "info",
    ) -> None:
        self._http = http_client
        self._concurrency = concurrency
        self._safe_mode = safe_mode
        self._threshold_idx = self._SEVERITY_ORDER.index(
            severity_threshold if severity_threshold in self._SEVERITY_ORDER else "info"
        )
        self._templates: List[Dict[str, Any]] = _load_templates()
        self._sem = asyncio.Semaphore(concurrency)

    async def run(self, base_url: str) -> List[Dict[str, Any]]:
        """Run all templates against *base_url*.

        Args:
            base_url: Target base URL (e.g. ``"https://example.com"``).

        Returns:
            List of match result dicts for templates that triggered.
        """
        eligible = [t for t in self._templates if self._is_eligible(t)]
        logger.debug(
            "Running %d/%d templates against %s",
            len(eligible),
            len(self._templates),
            base_url,
        )

        tasks = [self._run_template(t, base_url) for t in eligible]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        matches: List[Dict[str, Any]] = []
        for r in results:
            if isinstance(r, dict):
                matches.append(r)
            elif isinstance(r, Exception):
                logger.debug("Template check error: %s", r)

        return matches

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _is_eligible(self, template: Dict[str, Any]) -> bool:
        """Determine whether a template should be run given current settings.

        Args:
            template: Template dict.

        Returns:
            ``True`` if the template meets the severity threshold and safe-mode
            constraints.
        """
        sev = template.get("severity", "info")
        sev_idx = self._SEVERITY_ORDER.index(sev) if sev in self._SEVERITY_ORDER else 0
        if sev_idx < self._threshold_idx:
            return False
        if self._safe_mode and template.get("destructive", False):
            return False
        return True

    async def _run_template(
        self, template: Dict[str, Any], base_url: str
    ) -> Optional[Dict[str, Any]]:
        """Execute a single template against *base_url*.

        Args:
            template: Template dict.
            base_url: Target base URL.

        Returns:
            Match result dict if the template triggered, otherwise ``None``.
        """
        async with self._sem:
            req = template.get("request", {})
            method: str = req.get("method", "GET").upper()
            path: str = req.get("path", "/")
            extra_headers: Dict[str, str] = req.get("headers", {})
            body: Optional[str] = req.get("body")
            matchers: List[Dict[str, Any]] = template.get("matchers", [])

            url = base_url.rstrip("/") + path

            try:
                resp = await self._http.request(
                    method=method,
                    url=url,
                    headers=extra_headers,
                    data=body.encode() if body else None,
                )
            except Exception as exc:  # noqa: BLE001
                logger.debug("Template %s request failed: %s", template.get("id"), exc)
                return None

            if self._check_matchers(resp, matchers):
                return {
                    "template_id": template.get("id"),
                    "name": template.get("name"),
                    "severity": template.get("severity", "info"),
                    "category": template.get("category", ""),
                    "url": url,
                    "remediation": template.get("remediation", ""),
                    "status_code": resp.get("status"),
                }

            return None

    @staticmethod
    def _check_matchers(
        resp: Dict[str, Any], matchers: List[Dict[str, Any]]
    ) -> bool:
        """Evaluate all matchers against an HTTP response.

        All matchers must pass (logical AND) for the template to trigger.

        Args:
            resp: Response dict from :class:`~godrecon.utils.http_client.AsyncHTTPClient`.
            matchers: List of matcher dicts from the template.

        Returns:
            ``True`` if all matchers pass.
        """
        if not matchers:
            return False

        status: int = resp.get("status", 0)
        body: str = resp.get("body", "") or ""
        headers: Dict[str, str] = resp.get("headers", {}) or {}

        for matcher in matchers:
            mtype = matcher.get("type", "")
            value = matcher.get("value", "")

            if mtype == "status":
                try:
                    if status != int(value):
                        return False
                except (ValueError, TypeError):
                    return False

            elif mtype == "body_contains":
                if value.lower() not in body.lower():
                    return False

            elif mtype == "header_contains":
                hdr_key: str = matcher.get("key", "")
                hdr_val = headers.get(hdr_key, headers.get(hdr_key.lower(), ""))
                if value.lower() not in str(hdr_val).lower():
                    return False

            elif mtype == "body_regex":
                try:
                    if not re.search(value, body, re.IGNORECASE | re.MULTILINE):
                        return False
                except re.error:
                    return False

        return True
