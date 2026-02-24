"""Vulnerability detection module entry point for GODRECON.

Orchestrates CVE lookup, pattern-based vulnerability detection, and security
posture scoring.  Auto-discovered by the scan engine via the ``vulns``
package ``__init__.py`` export.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult
from godrecon.modules.vulns.cve_lookup import CVELookup
from godrecon.modules.vulns.pattern_matcher import PatternMatcher
from godrecon.modules.vulns.posture import SecurityPostureScorer
from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_DEFAULT_CONCURRENCY = 20
_DEFAULT_MAX_CVE_RESULTS = 20
_DEFAULT_SAFE_MODE = True
_DEFAULT_SEVERITY_THRESHOLD = "info"


class VulnerabilityModule(BaseModule):
    """Vulnerability detection and security posture assessment.

    Runs three sub-checks concurrently:

    1. CVE lookup — queries CVE.circl.lu for CVEs affecting detected technologies.
    2. Pattern matching — runs Nuclei-style templates against the target.
    3. Security posture scoring — aggregates all findings into a grade.
    """

    name = "vulns"
    description = "CVE lookup, pattern-based vuln detection, and security posture scoring"
    author = "GODRECON Team"
    version = "1.0.0"
    category = "vulns"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        """Run all vulnerability detection sub-modules.

        Args:
            target: Domain or IP address to scan.
            config: Global scan configuration.

        Returns:
            :class:`ModuleResult` containing vulnerability findings and posture score.
        """
        result = ModuleResult(module_name=self.name, target=target)
        vulns_cfg = getattr(config, "vulns", None)

        enabled_cve = getattr(vulns_cfg, "cve_lookup", True)
        enabled_patterns = getattr(vulns_cfg, "pattern_matching", True)
        enabled_posture = getattr(vulns_cfg, "posture_scoring", True)
        max_cve = getattr(vulns_cfg, "max_cve_results", _DEFAULT_MAX_CVE_RESULTS)
        safe_mode = getattr(vulns_cfg, "safe_mode", _DEFAULT_SAFE_MODE)
        severity_threshold = getattr(vulns_cfg, "severity_threshold", _DEFAULT_SEVERITY_THRESHOLD)

        general = config.general
        timeout = general.timeout
        proxy = general.proxy
        user_agents = general.user_agents

        cve_findings: List[Dict[str, Any]] = []
        pattern_findings: List[Dict[str, Any]] = []

        async with AsyncHTTPClient(
            timeout=timeout,
            max_connections=_DEFAULT_CONCURRENCY,
            user_agents=user_agents,
            proxy=proxy,
            # SSL verification is intentionally disabled for vulnerability scanning
            # so targets with expired or self-signed certificates can be assessed.
            verify_ssl=False,
            retries=1,
            rate_limit=0.0,
        ) as http:
            tasks = []

            if enabled_cve:
                tasks.append(
                    asyncio.create_task(
                        self._run_cve_lookup(http, target, config, max_cve)
                    )
                )

            if enabled_patterns:
                tasks.append(
                    asyncio.create_task(
                        self._run_pattern_matcher(http, target, safe_mode, severity_threshold)
                    )
                )

            task_results = await asyncio.gather(*tasks, return_exceptions=True)

        task_idx = 0
        if enabled_cve:
            r = task_results[task_idx]
            task_idx += 1
            if isinstance(r, list):
                cve_findings = r
            elif isinstance(r, Exception):
                logger.warning("CVE lookup failed: %s", r)

        if enabled_patterns:
            r = task_results[task_idx]
            task_idx += 1
            if isinstance(r, list):
                pattern_findings = r
            elif isinstance(r, Exception):
                logger.warning("Pattern matching failed: %s", r)

        # Convert sub-findings into Finding objects
        for cve in cve_findings:
            result.findings.append(self._cve_to_finding(cve))

        for match in pattern_findings:
            result.findings.append(self._match_to_finding(match))

        # Posture scoring
        posture: Optional[Dict[str, Any]] = None
        if enabled_posture:
            try:
                scorer = SecurityPostureScorer({self.name: result})
                posture = scorer.score()
                result.findings.append(self._posture_to_finding(posture))
            except Exception as exc:  # noqa: BLE001
                logger.warning("Posture scoring failed: %s", exc)

        result.raw = {
            "cve_findings": cve_findings,
            "pattern_matches": pattern_findings,
            "posture": posture,
            "total_cves": len(cve_findings),
            "total_pattern_matches": len(pattern_findings),
        }

        logger.info(
            "Vuln scan for %s complete — %d CVEs, %d pattern matches, %d total findings",
            target,
            len(cve_findings),
            len(pattern_findings),
            len(result.findings),
        )
        return result

    # ------------------------------------------------------------------
    # Sub-module runners
    # ------------------------------------------------------------------

    async def _run_cve_lookup(
        self,
        http: AsyncHTTPClient,
        target: str,
        config: Config,
        max_cve: int,
    ) -> List[Dict[str, Any]]:
        """Run CVE lookup for technologies detected on *target*.

        Args:
            http: Shared HTTP client.
            target: Scan target.
            config: Global configuration.
            max_cve: Maximum CVEs per technology.

        Returns:
            List of CVE finding dicts.
        """
        # Pull detected technologies from the tech module result if available
        technologies = self._extract_technologies(config)
        if not technologies:
            logger.debug("No technologies available for CVE lookup on %s", target)
            return []

        lookup = CVELookup(http_client=http, max_results=max_cve)
        cves = await lookup.lookup_technologies(technologies)
        return cves

    async def _run_pattern_matcher(
        self,
        http: AsyncHTTPClient,
        target: str,
        safe_mode: bool,
        severity_threshold: str,
    ) -> List[Dict[str, Any]]:
        """Run pattern-based checks against *target*.

        Args:
            http: Shared HTTP client.
            target: Scan target (domain or IP).
            safe_mode: Skip destructive templates when ``True``.
            severity_threshold: Minimum severity to run.

        Returns:
            List of pattern match dicts.
        """
        # Build a base URL — try HTTPS first as most targets support it
        base_url = f"https://{target}" if not target.startswith("http") else target

        matcher = PatternMatcher(
            http_client=http,
            concurrency=_DEFAULT_CONCURRENCY,
            safe_mode=safe_mode,
            severity_threshold=severity_threshold,
        )
        matches = await matcher.run(base_url)

        # If HTTPS fails completely try HTTP
        if not matches:
            http_base = f"http://{target}" if not target.startswith("http") else target
            if http_base != base_url:
                matches = await matcher.run(http_base)

        return matches

    # ------------------------------------------------------------------
    # Finding builders
    # ------------------------------------------------------------------

    @staticmethod
    def _cve_to_finding(cve: Dict[str, Any]) -> Finding:
        """Convert a CVE dict into a :class:`Finding`.

        Args:
            cve: CVE dict from :class:`~godrecon.modules.vulns.cve_lookup.CVELookup`.

        Returns:
            :class:`Finding` instance.
        """
        cve_id = cve.get("id", "Unknown CVE")
        tech = cve.get("technology", "unknown technology")
        version = cve.get("detected_version", "")
        summary = cve.get("summary", "")
        cvss = cve.get("cvss", 0.0)
        severity = cve.get("severity", "info")

        version_str = f" {version}" if version and version != "unknown" else ""
        title = f"{cve_id} — {tech}{version_str}"

        desc_parts = [f"CVE: {cve_id}", f"Technology: {tech}{version_str}"]
        if cvss:
            desc_parts.append(f"CVSS Score: {cvss}")
        if summary:
            desc_parts.append(f"Summary: {summary}")
        refs = cve.get("references", [])
        if refs:
            desc_parts.append("References: " + ", ".join(refs[:3]))

        return Finding(
            title=title,
            description="\n".join(desc_parts),
            severity=severity,
            data=cve,
            tags=["cve", "vulnerability", tech.lower()],
        )

    @staticmethod
    def _match_to_finding(match: Dict[str, Any]) -> Finding:
        """Convert a pattern match dict into a :class:`Finding`.

        Args:
            match: Match dict from :class:`~godrecon.modules.vulns.pattern_matcher.PatternMatcher`.

        Returns:
            :class:`Finding` instance.
        """
        name = match.get("name", "Unknown Template")
        category = match.get("category", "")
        url = match.get("url", "")
        severity = match.get("severity", "info")
        remediation = match.get("remediation", "")
        template_id = match.get("template_id", "")

        title = f"{name}: {url}"
        desc_parts = [f"Template: {template_id}", f"URL: {url}"]
        if category:
            desc_parts.append(f"Category: {category}")
        if remediation:
            desc_parts.append(f"Remediation: {remediation}")

        return Finding(
            title=title,
            description="\n".join(desc_parts),
            severity=severity,
            data=match,
            tags=["pattern-match", category, "vulnerability"],
        )

    @staticmethod
    def _posture_to_finding(posture: Dict[str, Any]) -> Finding:
        """Convert a posture score dict into a summary :class:`Finding`.

        Args:
            posture: Posture score dict from
                :class:`~godrecon.modules.vulns.posture.SecurityPostureScorer`.

        Returns:
            :class:`Finding` instance.
        """
        score = posture.get("overall_score", 0)
        grade = posture.get("grade", "?")
        summary = posture.get("summary", "")

        if score >= 90:
            severity = "info"
        elif score >= 70:
            severity = "low"
        elif score >= 50:
            severity = "medium"
        else:
            severity = "high"

        return Finding(
            title=f"Security Posture Score: {score}/100 (Grade {grade})",
            description=summary,
            severity=severity,
            data=posture,
            tags=["posture", "score", "summary"],
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_technologies(config: Config) -> List[Dict[str, Any]]:
        """Extract detected technology list from config context.

        Currently returns an empty list — in a full integration the scan
        engine would pass inter-module data.  Templates and passive heuristics
        are the primary detection path in this module.

        Args:
            config: Global scan configuration.

        Returns:
            List of technology dicts (may be empty).
        """
        # Placeholder: In a full integration technologies would be passed
        # from the tech detection module via the scan context.
        return []
