"""HTTP/HTTPS probing module entry point for GODRECON.

This module is auto-discovered by the :class:`~godrecon.core.engine.ScanEngine`
via the ``probe`` sub-module convention.  It orchestrates HTTP probing,
security-header analysis, and CORS checks for the scan target.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult
from godrecon.modules.http.cors import CORSAnalyzer
from godrecon.modules.http.http_probe import HTTPProber, ProbeResult
from godrecon.modules.http.security_headers import SecurityHeadersAnalyzer
from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)


class HTTPProbeModule(BaseModule):
    """HTTP/HTTPS probing, security-header analysis, and CORS detection.

    Probes the scan target on standard and alternative ports, analyses
    security headers on all responding services, and checks for CORS
    misconfigurations.
    """

    name = "http"
    description = "HTTP/HTTPS probing, security headers, and CORS analysis"
    author = "GODRECON Team"
    version = "1.0.0"
    category = "http"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        """Run HTTP probing and analysis for *target*.

        Args:
            target: Domain or IP address to probe.
            config: Scan configuration.

        Returns:
            :class:`ModuleResult` containing HTTP findings.
        """
        result = ModuleResult(module_name=self.name, target=target)
        http_cfg = config.http_probe

        async with AsyncHTTPClient(
            timeout=http_cfg.timeout,
            max_connections=http_cfg.concurrency,
            user_agents=config.general.user_agents,
            proxy=config.general.proxy,
            verify_ssl=False,
            retries=1,
        ) as http:
            prober = HTTPProber(
                http_client=http,
                ports=list(http_cfg.ports),
                concurrency=http_cfg.concurrency,
                timeout=http_cfg.timeout,
                follow_redirects=http_cfg.follow_redirects,
                max_redirects=http_cfg.max_redirects,
            )

            probe_results = await prober.probe_target(target)

        # Build findings for live hosts
        live_hosts: List[Dict[str, Any]] = []
        for pr in probe_results:
            live_hosts.append(pr.to_dict())
            self._add_probe_finding(result, pr)

        if not probe_results:
            result.findings.append(
                Finding(
                    title=f"No HTTP Services Found: {target}",
                    description="No HTTP or HTTPS services responded on checked ports.",
                    severity="info",
                    tags=["http", "probe"],
                )
            )
            result.raw = {"live_hosts": []}
            return result

        # Security headers and CORS checks
        async with AsyncHTTPClient(
            timeout=http_cfg.timeout,
            max_connections=http_cfg.concurrency,
            user_agents=config.general.user_agents,
            proxy=config.general.proxy,
            verify_ssl=False,
            retries=1,
        ) as http2:
            cors_analyzer = CORSAnalyzer(http_client=http2, concurrency=20)

            tasks = []
            if http_cfg.check_security_headers:
                for pr in probe_results:
                    tasks.append(
                        asyncio.create_task(
                            self._run_safe(
                                "sec_headers",
                                self._analyze_security_headers(result, pr),
                            )
                        )
                    )
            if http_cfg.check_cors:
                for pr in probe_results:
                    tasks.append(
                        asyncio.create_task(
                            self._run_safe(
                                "cors",
                                self._analyze_cors(result, pr, cors_analyzer, target),
                            )
                        )
                    )
            if tasks:
                await asyncio.gather(*tasks)

        result.raw = {"live_hosts": live_hosts}
        logger.info(
            "HTTP probe for %s complete — %d live hosts, %d findings",
            target,
            len(probe_results),
            len(result.findings),
        )
        return result

    # ------------------------------------------------------------------
    # Finding builders
    # ------------------------------------------------------------------

    @staticmethod
    def _add_probe_finding(result: ModuleResult, pr: ProbeResult) -> None:
        """Add an info-level finding for a live HTTP host.

        Args:
            result: Module result to append to.
            pr: Probe result for the host.
        """
        parts = [f"Status: {pr.status_code}"]
        if pr.title:
            parts.append(f"Title: {pr.title}")
        if pr.server:
            parts.append(f"Server: {pr.server}")
        if pr.content_type:
            parts.append(f"Content-Type: {pr.content_type}")
        parts.append(f"Response time: {pr.response_time}s")

        result.findings.append(
            Finding(
                title=f"Live HTTP Service: {pr.url}",
                description="\n".join(parts),
                severity="info",
                data=pr.to_dict(),
                tags=["http", "live", "probe"],
            )
        )

    @staticmethod
    async def _analyze_security_headers(
        result: ModuleResult, pr: ProbeResult
    ) -> None:
        """Run security-header analysis and append findings.

        Args:
            result: Module result to append to.
            pr: Probe result containing response headers.
        """
        analyzer = SecurityHeadersAnalyzer(pr.headers, url=pr.url)
        analysis = analyzer.analyze()

        severity = "info"
        if analysis["score"] < 45:
            severity = "high"
        elif analysis["score"] < 65:
            severity = "medium"
        elif analysis["score"] < 80:
            severity = "low"

        if analysis["issues"]:
            result.findings.append(
                Finding(
                    title=f"Security Headers Analysis: {pr.url}",
                    description=(
                        f"Security score: {analysis['score']}/100 (grade {analysis['grade']}). "
                        f"Missing/misconfigured headers: "
                        + ", ".join(i["header"] for i in analysis["issues"][:5])
                    ),
                    severity=severity,
                    data=analysis,
                    tags=["http", "security-headers"],
                )
            )
            # Individual finding for missing HSTS
            for issue in analysis["issues"]:
                if issue["header"] == "Strict-Transport-Security" and "missing" in issue["issue"].lower():
                    result.findings.append(
                        Finding(
                            title=f"Missing HSTS: {pr.url}",
                            description=issue["issue"] + ". " + issue.get("recommendation", ""),
                            severity="medium",
                            data=issue,
                            tags=["http", "hsts", "security-headers"],
                        )
                    )
                elif issue["header"] == "Content-Security-Policy" and "missing" in issue["issue"].lower():
                    result.findings.append(
                        Finding(
                            title=f"Missing CSP: {pr.url}",
                            description=issue["issue"] + ". " + issue.get("recommendation", ""),
                            severity="medium",
                            data=issue,
                            tags=["http", "csp", "security-headers"],
                        )
                    )

    @staticmethod
    async def _analyze_cors(
        result: ModuleResult,
        pr: ProbeResult,
        analyzer: CORSAnalyzer,
        target: str,
    ) -> None:
        """Run CORS checks and append findings.

        Args:
            result: Module result to append to.
            pr: Probe result containing the URL to check.
            analyzer: :class:`CORSAnalyzer` instance.
            target: Base target domain.
        """
        cors_result = await analyzer.analyze(pr.url, target)
        if cors_result.get("vulnerable"):
            for finding in cors_result.get("findings", []):
                result.findings.append(
                    Finding(
                        title=f"CORS Misconfiguration: {pr.url}",
                        description=finding.get("description", "CORS issue detected"),
                        severity=finding.get("severity", "medium"),
                        data=finding,
                        tags=["http", "cors", "misconfiguration"],
                    )
                )
        elif cors_result.get("findings"):
            # Wildcard without credentials — informational
            for finding in cors_result.get("findings", []):
                if finding.get("type") == "wildcard_cors":
                    result.findings.append(
                        Finding(
                            title=f"CORS Wildcard: {pr.url}",
                            description=finding.get("description", ""),
                            severity="medium",
                            data=finding,
                            tags=["http", "cors"],
                        )
                    )

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    async def _run_safe(name: str, coro: Any) -> None:
        """Run a coroutine, swallowing exceptions.

        Args:
            name: Human-readable sub-check name for logging.
            coro: Coroutine to await.
        """
        try:
            await coro
        except Exception as exc:  # noqa: BLE001
            logger.warning("HTTP sub-check '%s' failed: %s", name, exc)
