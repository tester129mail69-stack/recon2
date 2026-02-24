"""Email security analyzer for GODRECON.

Analyses SPF, DMARC, DKIM, BIMI, and MTA-STS records for a target domain.
Also probes SMTP servers for STARTTLS support and software banners.
"""

from __future__ import annotations

import asyncio
import re
import socket
from typing import Any, Dict, List, Optional

from godrecon.utils.dns_resolver import AsyncDNSResolver
from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# Common DKIM selectors to probe
DEFAULT_DKIM_SELECTORS: List[str] = [
    "default", "google", "selector1", "selector2", "k1", "k2",
    "dkim", "mail", "email", "s1", "s2", "mandrill", "amazonses",
    "cm", "protonmail", "zoho",
]


class EmailSecurityAnalyzer:
    """Analyse email security configuration for a domain.

    Checks SPF, DMARC, DKIM, BIMI, MTA-STS, and SMTP servers.

    Example::

        async with AsyncDNSResolver() as resolver:
            async with AsyncHTTPClient() as http:
                analyzer = EmailSecurityAnalyzer(resolver, http)
                result = await analyzer.analyze("example.com")
    """

    def __init__(
        self,
        resolver: AsyncDNSResolver,
        http_client: AsyncHTTPClient,
        dkim_selectors: Optional[List[str]] = None,
        smtp_timeout: int = 5,
    ) -> None:
        """Initialise the analyzer.

        Args:
            resolver: Configured DNS resolver instance.
            http_client: Configured HTTP client instance.
            dkim_selectors: DKIM selectors to probe (defaults to built-in list).
            smtp_timeout: Timeout in seconds for SMTP banner grabs.
        """
        self._resolver = resolver
        self._http = http_client
        self._dkim_selectors = dkim_selectors or DEFAULT_DKIM_SELECTORS
        self._smtp_timeout = smtp_timeout

    async def analyze(self, domain: str) -> Dict[str, Any]:
        """Run all email security checks for *domain*.

        Args:
            domain: Target domain.

        Returns:
            Dict with ``spf``, ``dmarc``, ``dkim``, ``bimi``, ``mta_sts``,
            and ``mail_servers`` sub-dicts.
        """
        spf, dmarc, dkim, bimi, mta_sts, mail_servers = await asyncio.gather(
            self._analyze_spf(domain),
            self._analyze_dmarc(domain),
            self._analyze_dkim(domain),
            self._analyze_bimi(domain),
            self._analyze_mta_sts(domain),
            self._analyze_mail_servers(domain),
        )
        return {
            "spf": spf,
            "dmarc": dmarc,
            "dkim": dkim,
            "bimi": bimi,
            "mta_sts": mta_sts,
            "mail_servers": mail_servers,
        }

    # ------------------------------------------------------------------
    # SPF
    # ------------------------------------------------------------------

    async def _analyze_spf(self, domain: str) -> Dict[str, Any]:
        """Parse and evaluate the SPF record for *domain*.

        Args:
            domain: Target domain.

        Returns:
            SPF analysis dict.
        """
        txt_records = await self._safe_resolve(domain, "TXT")
        spf_record: Optional[str] = None
        for rec in txt_records:
            if rec.strip().startswith("v=spf1"):
                spf_record = rec.strip()
                break

        if not spf_record:
            return {
                "record": None,
                "present": False,
                "issues": ["No SPF record found"],
                "score": 0,
            }

        issues: List[str] = []
        score = 100

        # Check for overly permissive all mechanisms
        if "+all" in spf_record:
            issues.append("SPF uses '+all' — allows any server to send mail (very permissive)")
            score -= 50
        elif "?all" in spf_record:
            issues.append("SPF uses '?all' — neutral result for unmatched senders (permissive)")
            score -= 20
        elif "~all" in spf_record:
            # softfail is acceptable but not ideal
            issues.append("SPF uses '~all' (softfail) — consider using '-all' for strict enforcement")
            score -= 5

        # Count DNS lookup mechanisms (max 10 per RFC 7208)
        lookup_mechanisms = re.findall(
            r"\b(include|a|mx|ptr|exists|redirect):", spf_record, re.IGNORECASE
        )
        dns_lookups = len(lookup_mechanisms)
        if dns_lookups > 10:
            issues.append(f"SPF exceeds 10 DNS lookup limit ({dns_lookups} lookups) — may cause failures")
            score -= 20
        elif dns_lookups > 7:
            issues.append(f"SPF is approaching the 10 DNS lookup limit ({dns_lookups}/10)")
            score -= 5

        score = max(score, 0)
        return {
            "record": spf_record,
            "present": True,
            "dns_lookups": dns_lookups,
            "issues": issues,
            "score": score,
        }

    # ------------------------------------------------------------------
    # DMARC
    # ------------------------------------------------------------------

    async def _analyze_dmarc(self, domain: str) -> Dict[str, Any]:
        """Parse and evaluate the DMARC record for *domain*.

        Args:
            domain: Target domain.

        Returns:
            DMARC analysis dict.
        """
        dmarc_domain = f"_dmarc.{domain}"
        txt_records = await self._safe_resolve(dmarc_domain, "TXT")
        dmarc_record: Optional[str] = None
        for rec in txt_records:
            if "v=DMARC1" in rec:
                dmarc_record = rec.strip()
                break

        if not dmarc_record:
            return {
                "record": None,
                "present": False,
                "policy": None,
                "issues": ["No DMARC record found — domain is not protected against spoofing"],
                "score": 0,
            }

        issues: List[str] = []
        score = 100
        tags = self._parse_dmarc_tags(dmarc_record)

        policy = tags.get("p", "none").lower()
        if policy == "none":
            issues.append("DMARC policy is 'none' — emails are not rejected/quarantined")
            score -= 40
        elif policy == "quarantine":
            score -= 10  # Good but not strictest

        # Subdomain policy
        sp = tags.get("sp", policy).lower()
        if sp == "none":
            issues.append("DMARC subdomain policy (sp) is 'none'")
            score -= 10

        # Reporting URIs
        if "rua" not in tags:
            issues.append("No aggregate report URI (rua) configured in DMARC")
            score -= 5

        # Alignment mode (informational — no score impact)
        adkim = tags.get("adkim", "r")
        aspf = tags.get("aspf", "r")
        if adkim == "r":
            issues.append("DKIM alignment is relaxed (adkim=r); consider strict (adkim=s) [informational]")
        if aspf == "r":
            issues.append("SPF alignment is relaxed (aspf=r); consider strict (aspf=s) [informational]")

        score = max(score, 0)
        return {
            "record": dmarc_record,
            "present": True,
            "policy": policy,
            "subdomain_policy": sp,
            "rua": tags.get("rua"),
            "ruf": tags.get("ruf"),
            "adkim": adkim,
            "aspf": aspf,
            "tags": tags,
            "issues": issues,
            "score": score,
        }

    @staticmethod
    def _parse_dmarc_tags(record: str) -> Dict[str, str]:
        """Parse DMARC tag=value pairs from *record*.

        Args:
            record: Raw DMARC TXT record string.

        Returns:
            Dict of tag names to values.
        """
        tags: Dict[str, str] = {}
        for part in record.split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                tags[k.strip().lower()] = v.strip()
        return tags

    # ------------------------------------------------------------------
    # DKIM
    # ------------------------------------------------------------------

    async def _analyze_dkim(self, domain: str) -> Dict[str, Any]:
        """Probe common DKIM selectors for *domain*.

        Args:
            domain: Target domain.

        Returns:
            DKIM analysis dict.
        """
        found_selectors: List[Dict[str, Any]] = []

        async def _check_selector(selector: str) -> Optional[Dict[str, Any]]:
            dkim_domain = f"{selector}._domainkey.{domain}"
            records = await self._safe_resolve(dkim_domain, "TXT")
            for rec in records:
                if "v=DKIM1" in rec or "k=rsa" in rec or "p=" in rec:
                    key_size = self._estimate_dkim_key_size(rec)
                    issues: List[str] = []
                    if key_size and key_size < 1024:
                        issues.append(f"DKIM key size {key_size} bits is too small (minimum 1024)")
                    return {
                        "selector": selector,
                        "record": rec,
                        "key_size_bits": key_size,
                        "issues": issues,
                    }
            return None

        tasks = [asyncio.create_task(_check_selector(s)) for s in self._dkim_selectors]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict):
                found_selectors.append(r)

        return {
            "selectors_found": found_selectors,
            "count": len(found_selectors),
            "present": bool(found_selectors),
        }

    @staticmethod
    def _estimate_dkim_key_size(record: str) -> Optional[int]:
        """Estimate the DKIM public key size from the ``p=`` field.

        Approximates RSA key strength from base64-encoded public key length:
        - ~216 base64 chars → 1024-bit key
        - ~392 base64 chars → 2048-bit key

        Args:
            record: DKIM TXT record string.

        Returns:
            Estimated key size in bits, or ``None`` if indeterminate.
        """
        match = re.search(r"p=([A-Za-z0-9+/=]+)", record)
        if not match:
            return None
        b64_len = len(match.group(1))
        # These thresholds are empirical: base64(DER-encoded RSA public key)
        # 512-bit  ≈  <100 chars
        # 1024-bit ≈  100–299 chars
        # 2048-bit ≈  300–499 chars
        # 4096-bit ≈  500+ chars
        if b64_len < 100:
            return 512
        elif b64_len < 300:
            return 1024
        elif b64_len < 500:
            return 2048
        return 4096

    # ------------------------------------------------------------------
    # BIMI
    # ------------------------------------------------------------------

    async def _analyze_bimi(self, domain: str) -> Dict[str, Any]:
        """Check for a BIMI record for *domain*.

        Args:
            domain: Target domain.

        Returns:
            BIMI analysis dict.
        """
        bimi_domain = f"default._bimi.{domain}"
        records = await self._safe_resolve(bimi_domain, "TXT")
        bimi_record: Optional[str] = None
        for rec in records:
            if "v=BIMI1" in rec:
                bimi_record = rec.strip()
                break

        if not bimi_record:
            return {"record": None, "present": False}

        has_vmc = "a=" in bimi_record and bimi_record.split("a=")[-1].strip() not in ("", ";")
        return {
            "record": bimi_record,
            "present": True,
            "has_vmc": has_vmc,
        }

    # ------------------------------------------------------------------
    # MTA-STS
    # ------------------------------------------------------------------

    async def _analyze_mta_sts(self, domain: str) -> Dict[str, Any]:
        """Check for MTA-STS DNS record and policy file for *domain*.

        Args:
            domain: Target domain.

        Returns:
            MTA-STS analysis dict.
        """
        mta_sts_domain = f"_mta-sts.{domain}"
        records = await self._safe_resolve(mta_sts_domain, "TXT")
        dns_record: Optional[str] = None
        for rec in records:
            if "v=STSv1" in rec:
                dns_record = rec.strip()
                break

        policy_text: Optional[str] = None
        policy_tags: Dict[str, str] = {}
        policy_error: Optional[str] = None

        if dns_record:
            policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
            try:
                resp = await self._http.get(policy_url)
                if resp.get("status") == 200:
                    policy_text = resp.get("body", "")
                    policy_tags = self._parse_mta_sts_policy(policy_text)
                else:
                    policy_error = f"Policy file returned HTTP {resp.get('status')}"
            except Exception as exc:  # noqa: BLE001
                policy_error = str(exc)

        mode = policy_tags.get("mode", "none") if policy_tags else None
        issues: List[str] = []
        if dns_record and not policy_text:
            issues.append(f"MTA-STS DNS record present but policy file not reachable: {policy_error}")
        if mode == "none":
            issues.append("MTA-STS mode is 'none' — not enforcing TLS")
        elif mode == "testing":
            issues.append("MTA-STS mode is 'testing' — consider moving to 'enforce'")

        return {
            "dns_record": dns_record,
            "present": bool(dns_record),
            "policy": policy_tags,
            "mode": mode,
            "issues": issues,
        }

    @staticmethod
    def _parse_mta_sts_policy(text: str) -> Dict[str, str]:
        """Parse an MTA-STS policy file into a dict.

        Args:
            text: Policy file text content.

        Returns:
            Dict of policy tag names to values.
        """
        tags: Dict[str, str] = {}
        for line in (text or "").splitlines():
            line = line.strip()
            if ":" in line:
                k, _, v = line.partition(":")
                tags[k.strip().lower()] = v.strip()
        return tags

    # ------------------------------------------------------------------
    # Mail servers
    # ------------------------------------------------------------------

    async def _analyze_mail_servers(self, domain: str) -> Dict[str, Any]:
        """Probe MX records and SMTP servers for *domain*.

        Args:
            domain: Target domain.

        Returns:
            Mail server analysis dict.
        """
        mx_raw = await self._safe_resolve(domain, "MX")
        mx_servers: List[Dict[str, Any]] = []
        for entry in mx_raw:
            parts = entry.split(" ", 1)
            host = parts[1].rstrip(".") if len(parts) == 2 else entry.rstrip(".")
            priority = int(parts[0]) if len(parts) == 2 else 0
            smtp_info = await self._grab_smtp_banner(host)
            mx_servers.append({"priority": priority, "host": host, **smtp_info})

        return {"mx_records": mx_servers, "count": len(mx_servers)}

    async def _grab_smtp_banner(self, host: str) -> Dict[str, Any]:
        """Attempt SMTP banner grab and STARTTLS check on *host*.

        Tries port 25, then 587.

        Args:
            host: Mail server hostname.

        Returns:
            Dict with ``banner``, ``starttls``, and ``open`` keys.
        """
        loop = asyncio.get_event_loop()
        for port in (25, 587):
            try:
                result = await asyncio.wait_for(
                    loop.run_in_executor(None, self._smtp_probe, host, port),
                    timeout=float(self._smtp_timeout),
                )
                if result.get("open"):
                    return result
            except Exception:  # noqa: BLE001
                continue
        return {"open": False, "banner": None, "starttls": False, "port": None}

    def _smtp_probe(self, host: str, port: int) -> Dict[str, Any]:
        """Synchronous SMTP probe (runs in executor).

        Args:
            host: Mail server hostname.
            port: SMTP port (25 or 587).

        Returns:
            Dict with connection and capability details.
        """
        try:
            with socket.create_connection((host, port), timeout=self._smtp_timeout) as s:
                banner = s.recv(1024).decode("utf-8", errors="replace").strip()
                # Send EHLO
                s.sendall(b"EHLO godrecon\r\n")
                ehlo = s.recv(4096).decode("utf-8", errors="replace")
                starttls = "STARTTLS" in ehlo.upper()
                s.sendall(b"QUIT\r\n")
                return {"open": True, "banner": banner, "starttls": starttls, "port": port}
        except Exception as exc:  # noqa: BLE001
            logger.debug("SMTP probe %s:%d: %s", host, port, exc)
            return {"open": False, "banner": None, "starttls": False, "port": port}

    async def _safe_resolve(self, domain: str, record_type: str) -> List[str]:
        """Resolve *record_type* for *domain*, returning ``[]`` on error.

        Args:
            domain: Domain name.
            record_type: DNS record type.

        Returns:
            List of record strings.
        """
        try:
            return await self._resolver.resolve(domain, record_type)
        except Exception as exc:  # noqa: BLE001
            logger.debug("EmailSec resolve %s %s: %s", record_type, domain, exc)
            return []
