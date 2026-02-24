"""DNS Intelligence Module for GODRECON.

Orchestrates all DNS analysis sub-modules concurrently and returns
comprehensive DNS findings as :class:`~godrecon.modules.base.Finding` objects.

This module covers:

* Complete DNS record resolution (all standard types)
* DNSSEC chain validation
* Zone transfer vulnerability check
* DNS security analysis (open resolvers, amplification, dangling CNAMEs…)
* Email security analysis (SPF, DMARC, DKIM, BIMI, MTA-STS, SMTP)
* Passive DNS history
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult
from godrecon.modules.dns.dnssec import DNSSECValidator
from godrecon.modules.dns.email_security import EmailSecurityAnalyzer
from godrecon.modules.dns.history import DNSHistoryChecker
from godrecon.modules.dns.records import DNSRecordResolver
from godrecon.modules.dns.security import DNSSecurityAnalyzer
from godrecon.modules.dns.zone_transfer import ZoneTransferChecker
from godrecon.utils.dns_resolver import AsyncDNSResolver
from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)


class DNSIntelModule(BaseModule):
    """Comprehensive DNS intelligence and security analysis module.

    Runs all DNS sub-modules concurrently and reports findings with
    appropriate severity levels.
    """

    name = "dns"
    description = "DNS intelligence: records, DNSSEC, zone transfer, email security"
    author = "GODRECON Team"
    version = "1.0.0"
    category = "dns"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        """Run all DNS intelligence checks for *target*.

        Args:
            target: Primary domain to analyse.
            config: Scan configuration.

        Returns:
            :class:`ModuleResult` containing DNS findings.
        """
        result = ModuleResult(module_name=self.name, target=target)
        dns_cfg = config.dns_module

        dkim_selectors = dns_cfg.dkim_selectors
        doh_enabled = dns_cfg.doh_enabled
        doh_server = dns_cfg.doh_server

        resolver_kwargs: Dict[str, Any] = {
            "nameservers": config.dns.resolvers,
            "timeout": config.dns.timeout,
        }
        if doh_enabled:
            resolver_kwargs["doh_enabled"] = True
            resolver_kwargs["doh_server"] = doh_server

        async with AsyncDNSResolver(**resolver_kwargs) as resolver:
            async with AsyncHTTPClient(
                timeout=config.general.timeout,
                user_agents=config.general.user_agents,
                proxy=config.general.proxy,
                verify_ssl=False,
            ) as http:
                record_resolver = DNSRecordResolver(resolver)
                dnssec_validator = DNSSECValidator(resolver)
                zt_checker = ZoneTransferChecker(resolver, timeout=config.dns.timeout)
                sec_analyzer = DNSSecurityAnalyzer(resolver, timeout=config.dns.timeout)
                email_analyzer = EmailSecurityAnalyzer(
                    resolver, http, dkim_selectors=dkim_selectors
                )
                history_checker = DNSHistoryChecker(http)

                (
                    dns_records,
                    dnssec_result,
                    zone_transfer_result,
                    security_result,
                    email_result,
                    history_result,
                ) = await asyncio.gather(
                    self._run_safe("records", record_resolver.resolve_all(target)),
                    self._run_safe("dnssec", dnssec_validator.validate(target)),
                    self._run_safe("zone_transfer", zt_checker.check(target)),
                    self._run_safe("security", sec_analyzer.analyze(target)),
                    self._run_safe("email_security", email_analyzer.analyze(target)),
                    self._run_safe("history", history_checker.check(target)),
                )

        # Build findings
        self._add_record_findings(result, dns_records, target)
        self._add_dnssec_findings(result, dnssec_result, target)
        self._add_zone_transfer_findings(result, zone_transfer_result, target)
        self._add_security_findings(result, security_result, target)
        self._add_email_security_findings(result, email_result, target)
        self._add_history_findings(result, history_result, target)

        result.raw = {
            "dns_records": dns_records,
            "dnssec": dnssec_result,
            "zone_transfer": zone_transfer_result,
            "security": security_result,
            "email_security": email_result,
            "history": history_result,
        }
        logger.info(
            "DNS intelligence for %s complete — %d findings",
            target,
            len(result.findings),
        )
        return result

    # ------------------------------------------------------------------
    # Safe task runner
    # ------------------------------------------------------------------

    @staticmethod
    async def _run_safe(name: str, coro: Any) -> Any:
        """Await *coro*, returning an empty dict on any exception.

        Args:
            name: Human-readable check name for logging.
            coro: Coroutine to await.

        Returns:
            Coroutine result or empty dict on error.
        """
        try:
            return await coro
        except Exception as exc:  # noqa: BLE001
            logger.warning("DNS sub-check '%s' failed: %s", name, exc)
            return {}

    # ------------------------------------------------------------------
    # Finding builders
    # ------------------------------------------------------------------

    @staticmethod
    def _add_record_findings(
        result: ModuleResult, records: Dict[str, Any], target: str
    ) -> None:
        """Add info-level findings for resolved DNS records.

        Args:
            result: Module result to append to.
            records: DNS records dict from :class:`DNSRecordResolver`.
            target: Target domain.
        """
        if not records:
            return
        summary_parts: List[str] = []
        for rtype, values in records.items():
            if values:
                summary_parts.append(f"{rtype}: {', '.join(str(v) for v in values[:5])}")

        result.findings.append(
            Finding(
                title=f"DNS Records: {target}",
                description="Resolved DNS records for the target domain.\n" + "\n".join(summary_parts),
                severity="info",
                data={"records": records},
                tags=["dns", "records"],
            )
        )

    @staticmethod
    def _add_dnssec_findings(
        result: ModuleResult, dnssec: Dict[str, Any], target: str
    ) -> None:
        """Add DNSSEC findings.

        Args:
            result: Module result to append to.
            dnssec: DNSSEC validation result dict.
            target: Target domain.
        """
        if not dnssec:
            return
        status = dnssec.get("status", "unknown")
        if status == "disabled":
            result.findings.append(
                Finding(
                    title=f"DNSSEC Not Enabled: {target}",
                    description="DNSSEC is not configured for this domain. "
                    "Enable DNSSEC to protect against DNS cache poisoning.",
                    severity="low",
                    data=dnssec,
                    tags=["dns", "dnssec", "security"],
                )
            )
        elif status == "misconfigured":
            result.findings.append(
                Finding(
                    title=f"DNSSEC Misconfigured: {target}",
                    description="DNSSEC records are present but the chain is incomplete: "
                    + "; ".join(dnssec.get("issues", [])),
                    severity="medium",
                    data=dnssec,
                    tags=["dns", "dnssec", "security"],
                )
            )
        else:
            result.findings.append(
                Finding(
                    title=f"DNSSEC Enabled: {target}",
                    description="DNSSEC is properly configured for this domain.",
                    severity="info",
                    data=dnssec,
                    tags=["dns", "dnssec"],
                )
            )

    @staticmethod
    def _add_zone_transfer_findings(
        result: ModuleResult, zt: Dict[str, Any], target: str
    ) -> None:
        """Add zone transfer findings.

        Args:
            result: Module result to append to.
            zt: Zone transfer check result dict.
            target: Target domain.
        """
        if not zt:
            return
        if zt.get("vulnerable"):
            result.findings.append(
                Finding(
                    title=f"Zone Transfer Allowed: {target}",
                    description=(
                        "One or more nameservers allow AXFR zone transfers, "
                        "exposing all DNS records to attackers. "
                        f"Vulnerable nameservers: {', '.join(zt.get('vulnerable_ns', []))}. "
                        "Restrict AXFR transfers to authorised secondaries only."
                    ),
                    severity="critical",
                    data=zt,
                    tags=["dns", "zone-transfer", "critical"],
                )
            )
        else:
            result.findings.append(
                Finding(
                    title=f"Zone Transfer Blocked: {target}",
                    description="All nameservers correctly refuse AXFR zone transfer requests.",
                    severity="info",
                    data=zt,
                    tags=["dns", "zone-transfer"],
                )
            )

    @staticmethod
    def _add_security_findings(
        result: ModuleResult, sec: Dict[str, Any], target: str
    ) -> None:
        """Add DNS security findings.

        Args:
            result: Module result to append to.
            sec: DNS security analysis result dict.
            target: Target domain.
        """
        if not sec:
            return
        for issue in sec.get("issues", []):
            severity = "high"
            if "open resolver" in issue.lower():
                severity = "high"
            elif "amplification" in issue.lower():
                severity = "high"
            elif "dangling" in issue.lower() or "takeover" in issue.lower():
                severity = "high"
            elif "rebinding" in issue.lower():
                severity = "medium"
            elif "recursion" in issue.lower():
                severity = "medium"
            result.findings.append(
                Finding(
                    title=f"DNS Security Issue: {target}",
                    description=issue,
                    severity=severity,
                    data=sec,
                    tags=["dns", "security"],
                )
            )

    @staticmethod
    def _add_email_security_findings(
        result: ModuleResult, email: Dict[str, Any], target: str
    ) -> None:
        """Add email security findings (SPF/DMARC/DKIM/BIMI/MTA-STS).

        Args:
            result: Module result to append to.
            email: Email security analysis result dict.
            target: Target domain.
        """
        if not email:
            return

        # SPF
        spf = email.get("spf", {})
        if not spf.get("present"):
            result.findings.append(
                Finding(
                    title=f"Missing SPF Record: {target}",
                    description="No SPF record found. Without SPF, anyone can send email claiming to be from this domain.",
                    severity="medium",
                    data=spf,
                    tags=["dns", "email", "spf"],
                )
            )
        else:
            for issue in spf.get("issues", []):
                severity = "high" if "+all" in issue else "medium"
                result.findings.append(
                    Finding(
                        title=f"SPF Issue: {target}",
                        description=issue,
                        severity=severity,
                        data=spf,
                        tags=["dns", "email", "spf"],
                    )
                )
            if not spf.get("issues"):
                result.findings.append(
                    Finding(
                        title=f"SPF Record Present: {target}",
                        description=f"SPF record found (score: {spf.get('score', 'N/A')}/100).",
                        severity="info",
                        data=spf,
                        tags=["dns", "email", "spf"],
                    )
                )

        # DMARC
        dmarc = email.get("dmarc", {})
        if not dmarc.get("present"):
            result.findings.append(
                Finding(
                    title=f"Missing DMARC Record: {target}",
                    description="No DMARC record found. DMARC protects against domain spoofing in email.",
                    severity="medium",
                    data=dmarc,
                    tags=["dns", "email", "dmarc"],
                )
            )
        else:
            policy = dmarc.get("policy", "none")
            if policy == "none":
                result.findings.append(
                    Finding(
                        title=f"DMARC Policy is 'none': {target}",
                        description="DMARC is configured but policy is 'none' — emails are not rejected or quarantined. Consider 'quarantine' or 'reject'.",
                        severity="medium",
                        data=dmarc,
                        tags=["dns", "email", "dmarc"],
                    )
                )
            else:
                result.findings.append(
                    Finding(
                        title=f"DMARC Configured: {target}",
                        description=f"DMARC policy: {policy} (score: {dmarc.get('score', 'N/A')}/100).",
                        severity="info",
                        data=dmarc,
                        tags=["dns", "email", "dmarc"],
                    )
                )

        # DKIM
        dkim = email.get("dkim", {})
        if not dkim.get("present"):
            result.findings.append(
                Finding(
                    title=f"No DKIM Selectors Found: {target}",
                    description="No DKIM public keys found under common selectors. DKIM signing may not be configured.",
                    severity="low",
                    data=dkim,
                    tags=["dns", "email", "dkim"],
                )
            )
        else:
            result.findings.append(
                Finding(
                    title=f"DKIM Selectors Found: {target}",
                    description=f"Found {dkim.get('count', 0)} DKIM selector(s): "
                    + ", ".join(s["selector"] for s in dkim.get("selectors_found", [])),
                    severity="info",
                    data=dkim,
                    tags=["dns", "email", "dkim"],
                )
            )

        # MTA-STS
        mta_sts = email.get("mta_sts", {})
        if not mta_sts.get("present"):
            result.findings.append(
                Finding(
                    title=f"MTA-STS Not Configured: {target}",
                    description="No MTA-STS record found. MTA-STS enforces TLS for inbound email.",
                    severity="low",
                    data=mta_sts,
                    tags=["dns", "email", "mta-sts"],
                )
            )

    @staticmethod
    def _add_history_findings(
        result: ModuleResult, history: Dict[str, Any], target: str
    ) -> None:
        """Add passive DNS history findings.

        Args:
            result: Module result to append to.
            history: DNS history result dict.
            target: Target domain.
        """
        if not history or not history.get("count"):
            return
        result.findings.append(
            Finding(
                title=f"Passive DNS Records: {target}",
                description=f"Found {history['count']} historical DNS records from passive DNS sources.",
                severity="info",
                data=history,
                tags=["dns", "passive-dns", "history"],
            )
        )
