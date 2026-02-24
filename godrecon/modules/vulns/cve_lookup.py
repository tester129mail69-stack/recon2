"""CVE Lookup module for GODRECON.

Queries the CVE.circl.lu API to find known CVEs for detected technologies.
Results are cached to avoid duplicate lookups and rate limiting is applied
to respect API limits.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_DATA_DIR = Path(__file__).parent.parent.parent / "data"
_CVE_PATTERNS_JSON = _DATA_DIR / "cve_patterns.json"

_CIRCL_API_BASE = "https://cve.circl.lu/api"
_DEFAULT_MAX_RESULTS = 20
_DEFAULT_RATE_LIMIT = 1.0  # seconds between requests


def _load_cpe_patterns() -> Dict[str, str]:
    """Load technology-to-CPE mapping from JSON data file.

    Returns:
        Dict mapping technology names to CPE strings.
    """
    try:
        with _CVE_PATTERNS_JSON.open("r") as fh:
            return json.load(fh)
    except Exception:  # noqa: BLE001
        return {}


class CVELookup:
    """CVE lookup engine using the CVE.circl.lu public API.

    Searches for known CVEs based on detected technology names and versions.
    Results are cached to avoid duplicate API calls.

    Args:
        http_client: Shared :class:`~godrecon.utils.http_client.AsyncHTTPClient` instance.
        max_results: Maximum CVE results to return per technology.
        rate_limit: Minimum seconds between API requests.
    """

    def __init__(
        self,
        http_client: AsyncHTTPClient,
        max_results: int = _DEFAULT_MAX_RESULTS,
        rate_limit: float = _DEFAULT_RATE_LIMIT,
    ) -> None:
        self._http = http_client
        self._max_results = max_results
        self._rate_limit = rate_limit
        self._cache: Dict[str, List[Dict[str, Any]]] = {}
        self._cpe_map: Dict[str, str] = _load_cpe_patterns()
        self._sem = asyncio.Semaphore(3)  # limit concurrent API calls

    async def lookup_technology(
        self, tech_name: str, version: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Look up CVEs for a detected technology.

        Args:
            tech_name: Technology name (e.g. ``"Apache"``, ``"Nginx"``).
            version: Optional version string to filter results.

        Returns:
            List of CVE dicts with ``id``, ``summary``, ``cvss``, ``severity``,
            and ``references`` keys.
        """
        cache_key = f"{tech_name}:{version or ''}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        cpe = self._cpe_map.get(tech_name) or self._cpe_map.get(tech_name.split("/")[0])
        if not cpe:
            logger.debug("No CPE mapping found for technology: %s", tech_name)
            self._cache[cache_key] = []
            return []

        cves = await self._fetch_cves_for_cpe(cpe, version)
        self._cache[cache_key] = cves
        return cves

    async def lookup_technologies(
        self, technologies: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Look up CVEs for a list of detected technologies.

        Args:
            technologies: List of technology dicts with at least a ``name`` key
                          and optionally a ``version`` key.

        Returns:
            Flat list of CVE finding dicts, each enriched with ``technology`` key.
        """
        tasks = []
        for tech in technologies:
            name = tech.get("name", "")
            version = tech.get("version")
            if name:
                tasks.append(self._lookup_with_context(name, version))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        findings: List[Dict[str, Any]] = []
        for r in results:
            if isinstance(r, list):
                findings.extend(r)
            elif isinstance(r, Exception):
                logger.debug("CVE lookup task error: %s", r)

        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _lookup_with_context(
        self, tech_name: str, version: Optional[str]
    ) -> List[Dict[str, Any]]:
        """Wrap :meth:`lookup_technology` to inject the tech name into results.

        Args:
            tech_name: Technology name.
            version: Optional version string.

        Returns:
            List of CVE dicts annotated with ``technology`` and ``version``.
        """
        cves = await self.lookup_technology(tech_name, version)
        for cve in cves:
            cve["technology"] = tech_name
            cve["detected_version"] = version or "unknown"
        return cves

    async def _fetch_cves_for_cpe(
        self, cpe: str, version: Optional[str]
    ) -> List[Dict[str, Any]]:
        """Fetch CVE data from CVE.circl.lu for a given CPE.

        Args:
            cpe: CPE 2.3 format string (e.g. ``"cpe:2.3:a:apache:http_server"``).
            version: Optional version to append to CPE.

        Returns:
            Parsed list of CVE dicts.
        """
        async with self._sem:
            if self._rate_limit > 0:
                await asyncio.sleep(self._rate_limit)

            cpe_query = cpe
            if version:
                cpe_query = f"{cpe}:{version}"

            url = f"{_CIRCL_API_BASE}/cvefor/{cpe_query}"
            try:
                resp = await self._http.get(url)
                if resp.get("status") != 200:
                    logger.debug("CVE API non-200 for %s: %s", cpe, resp.get("status"))
                    return []

                body = resp.get("body", "") or ""
                try:
                    raw = json.loads(body) if body else []
                except json.JSONDecodeError:
                    return []
                if not isinstance(raw, list):
                    return []

                return [self._parse_cve(c) for c in raw[: self._max_results] if isinstance(c, dict)]
            except Exception as exc:  # noqa: BLE001
                logger.debug("CVE API request failed for %s: %s", cpe, exc)
                return []

    @staticmethod
    def _parse_cve(raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalise a raw CVE dict from the circl.lu API.

        Args:
            raw: Raw API response dict for a single CVE.

        Returns:
            Normalised CVE dict.
        """
        cvss = raw.get("cvss") or raw.get("cvss3") or 0.0
        try:
            cvss = float(cvss)
        except (TypeError, ValueError):
            cvss = 0.0

        severity = _cvss_to_severity(cvss)

        return {
            "id": raw.get("id", ""),
            "summary": raw.get("summary", "No description available"),
            "cvss": cvss,
            "severity": severity,
            "published": raw.get("Published", ""),
            "modified": raw.get("Modified", ""),
            "references": raw.get("references", []),
            "cwe": raw.get("cwe", ""),
        }


def _cvss_to_severity(cvss: float) -> str:
    """Convert a CVSS score to a severity label.

    Args:
        cvss: CVSS score (0.0 – 10.0).

    Returns:
        Severity label string: ``"critical"``, ``"high"``, ``"medium"``, ``"low"``,
        or ``"info"``.
    """
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0.0:
        return "low"
    return "info"
