"""SSL/TLS analysis module entry point for GODRECON.

Auto-discovered by the :class:`~godrecon.core.engine.ScanEngine` via the
``scanner`` sub-module convention.  Runs SSL/TLS certificate and protocol
analysis for the scan target.
"""

from __future__ import annotations

from typing import Any, Dict, List

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult
from godrecon.modules.ssl.ssl_analyzer import SSLAnalyzer
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# Ports to probe for TLS
_SSL_PORTS = [443, 8443, 4443]


class SSLAnalysisModule(BaseModule):
    """SSL/TLS certificate, protocol, cipher, and vulnerability analysis.

    Connects to common TLS ports on the target, analyses the certificate
    chain and TLS configuration, and produces graded security findings.
    """

    name = "ssl"
    description = "SSL/TLS certificate analysis, cipher enumeration, and vulnerability detection"
    author = "GODRECON Team"
    version = "1.0.0"
    category = "ssl"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        """Run SSL/TLS analysis for *target*.

        Args:
            target: Domain or IP to analyse.
            config: Scan configuration.

        Returns:
            :class:`ModuleResult` containing SSL/TLS findings.
        """
        result = ModuleResult(module_name=self.name, target=target)
        ssl_cfg = config.ssl_analysis
        timeout = config.general.timeout

        analyzer = SSLAnalyzer(timeout=float(timeout))

        all_ssl: List[Dict[str, Any]] = []
        for port in _SSL_PORTS:
            ssl_result = await self._run_safe(
                f"ssl:{port}", analyzer.analyze(target, port)
            )
            if ssl_result and not ssl_result.get("error"):
                all_ssl.append(ssl_result)
                self._build_findings(result, ssl_result, ssl_cfg)
            elif ssl_result and ssl_result.get("error"):
                logger.debug("SSL analysis error for %s:%d: %s", target, port, ssl_result["error"])

        if not all_ssl:
            result.findings.append(
                Finding(
                    title=f"No TLS Services Found: {target}",
                    description="No TLS services were found on the checked ports (443, 8443, 4443).",
                    severity="info",
                    tags=["ssl", "tls"],
                )
            )
        else:
            result.raw = {"ssl_analysis": all_ssl}

        logger.info(
            "SSL analysis for %s complete — %d findings",
            target,
            len(result.findings),
        )
        return result

    # ------------------------------------------------------------------
    # Finding builders
    # ------------------------------------------------------------------

    def _build_findings(
        self, result: ModuleResult, ssl_result: Dict[str, Any], ssl_cfg: Any
    ) -> None:
        """Convert SSL analysis results into :class:`Finding` objects.

        Args:
            result: Module result to append to.
            ssl_result: Full SSL analysis dict from :class:`SSLAnalyzer`.
            ssl_cfg: SSL analysis configuration.
        """
        host = ssl_result.get("host", "")
        port = ssl_result.get("port", 443)
        cert = ssl_result.get("certificate", {})
        protocols = ssl_result.get("protocols", {})
        ciphers = ssl_result.get("ciphers", [])
        vulns = ssl_result.get("vulnerabilities", {})
        grade = ssl_result.get("grade", "N/A")
        score = ssl_result.get("score", 0)

        label = f"{host}:{port}"

        # Overall grade finding
        result.findings.append(
            Finding(
                title=f"SSL/TLS Grade {grade}: {label}",
                description=f"SSL/TLS configuration grade: {grade} (score: {score}/100)",
                severity="info" if grade in ("A+", "A", "B") else ("medium" if grade == "C" else "high"),
                data=ssl_result,
                tags=["ssl", "tls", "grade"],
            )
        )

        if not ssl_cfg.check_certificate:
            return

        # Certificate findings
        if cert.get("expired"):
            result.findings.append(
                Finding(
                    title=f"SSL Certificate Expired: {label}",
                    description=(
                        f"The SSL certificate for {label} has expired. "
                        f"Subject: {cert.get('subject', {})}"
                    ),
                    severity="critical",
                    data=cert,
                    tags=["ssl", "certificate", "expired"],
                )
            )
        elif cert.get("days_until_expiry", 365) < 30:
            days = cert.get("days_until_expiry", 0)
            result.findings.append(
                Finding(
                    title=f"SSL Certificate Expiring Soon: {label}",
                    description=f"Certificate expires in {days} days. Renew promptly.",
                    severity="high" if days < 7 else "medium",
                    data=cert,
                    tags=["ssl", "certificate", "expiry"],
                )
            )

        if cert.get("self_signed"):
            result.findings.append(
                Finding(
                    title=f"Self-Signed Certificate: {label}",
                    description=(
                        "The server is using a self-signed certificate. "
                        "Clients will receive browser security warnings."
                    ),
                    severity="medium",
                    data=cert,
                    tags=["ssl", "certificate", "self-signed"],
                )
            )

        if cert.get("wildcard"):
            result.findings.append(
                Finding(
                    title=f"Wildcard Certificate: {label}",
                    description=(
                        f"Wildcard certificate in use: {cert.get('subject', {}).get('commonName', '')}. "
                        "If the key is compromised, all subdomains are affected."
                    ),
                    severity="info",
                    data=cert,
                    tags=["ssl", "certificate", "wildcard"],
                )
            )

        if not ssl_cfg.check_protocols:
            return

        # Protocol version findings
        if protocols.get("TLSv1.0"):
            result.findings.append(
                Finding(
                    title=f"TLS 1.0 Enabled: {label}",
                    description=(
                        "TLS 1.0 is deprecated (RFC 8996) and vulnerable to POODLE/BEAST. "
                        "Disable TLS 1.0 in your server configuration."
                    ),
                    severity="medium",
                    data={"protocol": "TLSv1.0", "host": host, "port": port},
                    tags=["ssl", "tls", "protocol", "deprecated"],
                )
            )

        if protocols.get("TLSv1.1"):
            result.findings.append(
                Finding(
                    title=f"TLS 1.1 Enabled: {label}",
                    description=(
                        "TLS 1.1 is deprecated (RFC 8996). "
                        "Disable TLS 1.1 and use TLS 1.2 or 1.3 only."
                    ),
                    severity="medium",
                    data={"protocol": "TLSv1.1", "host": host, "port": port},
                    tags=["ssl", "tls", "protocol", "deprecated"],
                )
            )

        if not ssl_cfg.check_ciphers:
            return

        # Weak cipher findings
        weak_ciphers = [c for c in ciphers if c.get("weak")]
        if weak_ciphers:
            result.findings.append(
                Finding(
                    title=f"Weak Cipher Suites Supported: {label}",
                    description=(
                        f"{len(weak_ciphers)} weak cipher suite(s) supported: "
                        + ", ".join(c["name"] for c in weak_ciphers[:5])
                    ),
                    severity="high",
                    data={"weak_ciphers": weak_ciphers, "host": host, "port": port},
                    tags=["ssl", "tls", "ciphers", "weak"],
                )
            )

        if not ssl_cfg.check_vulnerabilities:
            return

        # Vulnerability findings
        if vulns.get("heartbleed", {}).get("vulnerable"):
            result.findings.append(
                Finding(
                    title=f"Heartbleed Vulnerable: {label}",
                    description=(
                        "The server appears vulnerable to Heartbleed (CVE-2014-0160). "
                        "Update OpenSSL immediately. This allows remote memory disclosure."
                    ),
                    severity="critical",
                    data=vulns.get("heartbleed", {}),
                    tags=["ssl", "vulnerability", "heartbleed", "cve-2014-0160"],
                )
            )

        if vulns.get("crime", {}).get("vulnerable"):
            result.findings.append(
                Finding(
                    title=f"CRIME/BREACH Vulnerable: {label}",
                    description=(
                        "TLS compression is enabled, making the server potentially "
                        "vulnerable to CRIME (CVE-2012-4929). Disable TLS compression."
                    ),
                    severity="medium",
                    data=vulns.get("crime", {}),
                    tags=["ssl", "vulnerability", "crime"],
                )
            )

        if vulns.get("freak", {}).get("vulnerable"):
            result.findings.append(
                Finding(
                    title=f"FREAK Vulnerable: {label}",
                    description=(
                        "Server supports EXPORT-grade ciphers (FREAK, CVE-2015-0204). "
                        "Disable all EXPORT ciphers immediately."
                    ),
                    severity="high",
                    data=vulns.get("freak", {}),
                    tags=["ssl", "vulnerability", "freak", "cve-2015-0204"],
                )
            )

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    async def _run_safe(name: str, coro: Any) -> Any:
        """Await *coro*, returning ``None`` on any exception.

        Args:
            name: Human-readable check name.
            coro: Coroutine to await.

        Returns:
            Result or ``None``.
        """
        try:
            return await coro
        except Exception as exc:  # noqa: BLE001
            logger.warning("SSL sub-check '%s' failed: %s", name, exc)
            return None
