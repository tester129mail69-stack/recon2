"""API intelligence module entry point for GODRECON.

Orchestrates API endpoint discovery and security analysis.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List

from godrecon.core.config import Config
from godrecon.modules.api_intel.discovery import APIDiscovery
from godrecon.modules.api_intel.security import APISecurityChecker
from godrecon.modules.base import BaseModule, Finding, ModuleResult
from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)


class APIIntelModule(BaseModule):
    """API intelligence: endpoint discovery, security analysis."""

    name = "api_intel"
    description = "API intelligence: endpoint discovery, security analysis"
    author = "GODRECON Team"
    version = "1.0.0"
    category = "api"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        """Run API discovery and security checks for *target*.

        Args:
            target: Domain name to investigate.
            config: Scan configuration.

        Returns:
            :class:`ModuleResult` with API findings.
        """
        result = ModuleResult(module_name=self.name, target=target)

        async with AsyncHTTPClient(
            timeout=config.general.timeout,
            user_agents=config.general.user_agents,
            proxy=config.general.proxy,
            verify_ssl=False,
            retries=1,
        ) as http:
            # Phase 1: Discover endpoints
            discovery = APIDiscovery()
            endpoints: List[Dict[str, Any]] = []
            try:
                endpoints = await discovery.discover(target, http)
            except Exception as exc:  # noqa: BLE001
                logger.warning("API discovery failed for %s: %s", target, exc)

            # Phase 2: Security checks on discovered endpoints (concurrent)
            checker = APISecurityChecker()
            security_tasks = [
                asyncio.create_task(checker.check(ep["url"], http))
                for ep in endpoints
                if ep.get("found") and ep.get("status") in (200, 401)
            ]
            security_results_raw = await asyncio.gather(
                *security_tasks, return_exceptions=True
            )

        result.raw["endpoints"] = endpoints
        security_findings: List[Dict[str, Any]] = []
        for sr in security_results_raw:
            if isinstance(sr, list):
                security_findings.extend(sr)

        result.raw["security_issues"] = security_findings

        # Create findings for discovered endpoints
        if endpoints:
            doc_endpoints = [e for e in endpoints if e.get("type") == "documentation"]
            api_endpoints = [e for e in endpoints if e.get("type") != "documentation"]

            result.findings.append(
                Finding(
                    title=f"API Endpoints Discovered ({len(endpoints)})",
                    description=(
                        f"Found {len(endpoints)} API endpoint(s): "
                        f"{len(doc_endpoints)} documentation, {len(api_endpoints)} API paths."
                    ),
                    severity="info",
                    data={"endpoints": [{"url": e["url"], "type": e["type"], "status": e["status"]} for e in endpoints]},
                    tags=["api", "discovery"],
                )
            )

            # GraphQL introspection is a notable finding
            graphql_open = [e for e in endpoints if e.get("type") == "graphql" and e.get("introspection_enabled")]
            if graphql_open:
                result.findings.append(
                    Finding(
                        title="GraphQL Introspection Enabled",
                        description=(
                            "GraphQL introspection is enabled, allowing an attacker to enumerate "
                            "the full schema, types, and queries. Disable in production."
                        ),
                        severity="medium",
                        data={"urls": [e["url"] for e in graphql_open]},
                        tags=["api", "graphql", "introspection"],
                    )
                )

        # Create findings from security checks
        for issue in security_findings:
            issue_type = issue.get("type", "api_issue")
            severity = issue.get("severity", "info")
            # Skip info-only "api_version_detected" from polluting findings
            if issue_type == "api_version_detected":
                continue
            result.findings.append(
                Finding(
                    title=self._issue_title(issue_type),
                    description=issue.get("description", ""),
                    severity=severity,
                    data=issue,
                    tags=["api", "security", issue_type],
                )
            )

        logger.info(
            "API intel for %s complete — %d endpoints, %d findings",
            target,
            len(endpoints),
            len(result.findings),
        )
        return result

    @staticmethod
    def _issue_title(issue_type: str) -> str:
        """Map an issue type key to a human-readable title.

        Args:
            issue_type: Internal issue type key.

        Returns:
            Human-readable title string.
        """
        titles = {
            "cors_wildcard": "API CORS Misconfiguration (Wildcard Origin)",
            "unauthenticated_access": "Unauthenticated API Access",
            "authentication_required": "API Authentication Required",
            "no_rate_limiting": "API Missing Rate Limiting",
            "verbose_errors": "API Returns Verbose Error Messages",
            "api_version_detected": "API Version Detected",
        }
        return titles.get(issue_type, f"API Security Issue: {issue_type}")
