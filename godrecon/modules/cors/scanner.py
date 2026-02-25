"""CORS misconfiguration detection module for GODRECON."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)


class CORSModule(BaseModule):
    """CORS misconfiguration detection."""

    name = "cors"
    description = "CORS misconfiguration detection"
    category = "vulns"
    version = "1.0.0"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        """Test CORS misconfigurations for the target."""
        result = ModuleResult(module_name=self.name, target=target)
        timeout = getattr(getattr(config, "general", None), "timeout", 10) or 10
        base_url = f"https://{target}" if not target.startswith("http") else target

        checks = [
            ("evil_origin", "https://evil.com"),
            ("subdomain_bypass", f"https://{target}.evil.com"),
            ("null_origin", "null"),
        ]

        for check_name, origin in checks:
            check_result = await self._run_safe(
                check_name,
                self._check_cors(base_url, origin, timeout),
            )
            if check_result:
                finding = self._build_finding(check_result, base_url, origin, check_name)
                if finding:
                    result.findings.append(finding)

        result.raw = {
            "target": target,
            "checks_performed": [c[0] for c in checks],
            "vulnerabilities_found": len(result.findings),
        }

        logger.info("CORS scan for %s: %d issues found", target, len(result.findings))
        return result

    @staticmethod
    async def _check_cors(url: str, origin: str, timeout: int = 10) -> Optional[Dict[str, Any]]:
        """Send request with given Origin header and check response."""
        try:
            import aiohttp
            headers = {"Origin": origin}
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    ssl=False,
                    allow_redirects=True,
                ) as resp:
                    acao = resp.headers.get("Access-Control-Allow-Origin", "")
                    acac = resp.headers.get("Access-Control-Allow-Credentials", "false").lower()
                    acam = resp.headers.get("Access-Control-Allow-Methods", "")
                    return {
                        "status": resp.status,
                        "acao": acao,
                        "acac": acac == "true",
                        "acam": acam,
                        "origin_sent": origin,
                    }
        except Exception as exc:
            logger.debug("CORS check error for %s with origin %s: %s", url, origin, exc)
            return None

    @staticmethod
    def _build_finding(
        check_result: Dict[str, Any],
        url: str,
        origin: str,
        check_name: str,
    ) -> Optional[Finding]:
        """Build a Finding from a CORS check result, or None if not vulnerable."""
        acao = check_result.get("acao", "")
        acac = check_result.get("acac", False)
        origin_sent = check_result.get("origin_sent", origin)

        if not acao:
            return None

        # Critical: wildcard with credentials
        if acao == "*" and acac:
            return Finding(
                title=f"CORS Critical: Wildcard origin with credentials — {url}",
                description=(
                    "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true.\n"
                    "This allows any website to make credentialed cross-origin requests.\n"
                    "Remediation: Never use wildcard origin with credentials. Specify exact origins."
                ),
                severity="critical",
                data=check_result,
                tags=["cors", "misconfiguration", "critical"],
            )

        # High: arbitrary origin reflected with credentials
        if acao == origin_sent and acac and origin_sent not in ("null", "*"):
            return Finding(
                title=f"CORS High: Reflected arbitrary origin with credentials — {url}",
                description=(
                    f"Origin '{origin_sent}' was reflected in Access-Control-Allow-Origin "
                    f"with Access-Control-Allow-Credentials: true.\n"
                    "This allows attackers to steal sensitive data via cross-origin requests.\n"
                    "Remediation: Validate Origin against a whitelist."
                ),
                severity="high",
                data=check_result,
                tags=["cors", "misconfiguration", "high"],
            )

        # Medium: null origin with credentials
        if acao == "null" and acac:
            return Finding(
                title=f"CORS Medium: Null origin allowed with credentials — {url}",
                description=(
                    "Origin 'null' is allowed with credentials. "
                    "This can be exploited via sandboxed iframes.\n"
                    "Remediation: Do not allow null origin with credentials."
                ),
                severity="medium",
                data=check_result,
                tags=["cors", "misconfiguration", "medium"],
            )

        # Low: reflected arbitrary origin without credentials
        if acao == origin_sent and not acac and origin_sent not in ("null", "*"):
            return Finding(
                title=f"CORS Low: Reflected arbitrary origin (no credentials) — {url}",
                description=(
                    f"Origin '{origin_sent}' was reflected in Access-Control-Allow-Origin "
                    f"without credentials. Low-risk but permissive CORS policy.\n"
                    "Remediation: Validate Origin against a whitelist."
                ),
                severity="low",
                data=check_result,
                tags=["cors", "misconfiguration", "low"],
            )

        return None

    @staticmethod
    async def _run_safe(name: str, coro: Any) -> Any:
        """Run a coroutine safely."""
        try:
            return await coro
        except Exception as exc:
            logger.warning("CORS sub-check '%s' failed: %s", name, exc)
            return None
