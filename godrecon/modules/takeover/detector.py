"""Subdomain takeover detection module for GODRECON.

Detects potential subdomain takeover vulnerabilities by checking CNAME records
against known vulnerable service fingerprints, verifying NXDOMAIN conditions,
and matching fingerprint strings in HTTP response bodies.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult
from godrecon.utils.dns_resolver import AsyncDNSResolver
from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_SUBDOMAIN_PREFIXES: List[str] = [
    "www", "mail", "blog", "shop", "cdn", "api",
    "dev", "staging", "test", "app", "portal", "admin",
    "status", "help", "support", "docs", "assets", "static",
    "media", "images", "files", "download", "ftp", "old",
]

_CONFIDENCE_SEVERITY: Dict[str, str] = {
    "confirmed": "critical",
    "high": "critical",
    "medium": "high",
    "low": "medium",
}


class TakeoverDetectorModule(BaseModule):
    """Subdomain takeover vulnerability detection module.

    Checks the target domain and common subdomains for potential takeover
    vulnerabilities by correlating CNAME records with known-vulnerable service
    fingerprints, NXDOMAIN conditions, and HTTP body fingerprints.
    """

    name = "takeover"
    description = "Subdomain takeover vulnerability detection"
    category = "takeover"
    version = "1.0.0"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        """Execute subdomain takeover detection for *target*.

        Args:
            target: Primary scan target (domain string).
            config: Global scan configuration.

        Returns:
            :class:`ModuleResult` containing takeover findings and raw data.
        """
        result = ModuleResult(module_name=self.name, target=target)

        takeover_cfg = getattr(config, "takeover", None)
        enabled = getattr(takeover_cfg, "enabled", True)
        check_all = getattr(takeover_cfg, "check_all_subdomains", True)

        if not enabled:
            result.raw = {"checked": 0, "vulnerable": [], "target": target}
            return result

        fingerprints = self._load_fingerprints()
        if not fingerprints:
            self.logger.warning("No takeover fingerprints loaded — skipping module.")
            result.raw = {"checked": 0, "vulnerable": [], "target": target}
            return result

        subdomains: List[str] = [target]
        if check_all:
            subdomains += [f"{prefix}.{target}" for prefix in _SUBDOMAIN_PREFIXES]

        concurrency = 20
        sem = asyncio.Semaphore(concurrency)
        vulnerable: List[Dict[str, Any]] = []

        async with AsyncDNSResolver() as dns_resolver:
            async with AsyncHTTPClient(timeout=10, max_connections=concurrency, verify_ssl=False, retries=1) as http_client:
                tasks = [
                    asyncio.create_task(
                        self._check_subdomain(sub, fingerprints, dns_resolver, http_client, sem)
                    )
                    for sub in subdomains
                ]
                check_results = await asyncio.gather(*tasks, return_exceptions=True)

        for sub, check_result in zip(subdomains, check_results):
            if isinstance(check_result, Exception):
                self.logger.debug("Check for %s raised exception: %s", sub, check_result)
                continue
            if check_result is None:
                continue
            vulnerable.append(check_result)
            confidence = check_result.get("confidence", "low")
            service = check_result.get("service", "Unknown")
            severity = _CONFIDENCE_SEVERITY.get(confidence, "medium")

            cname = check_result.get("cname", "")
            fp_matched = check_result.get("fingerprint_matched", "")
            nxdomain = check_result.get("nxdomain", False)

            desc_parts = [
                f"Subdomain: {sub}",
                f"CNAME: {cname}",
                f"Service: {service}",
                f"Confidence: {confidence}",
            ]
            if fp_matched:
                desc_parts.append(f"Fingerprint matched: {fp_matched!r}")
            if nxdomain:
                desc_parts.append("CNAME target resolves to NXDOMAIN (unclaimed resource)")

            result.findings.append(
                Finding(
                    title=f"Subdomain Takeover: {sub} -> {service}",
                    description="\n".join(desc_parts),
                    severity=severity,
                    data=check_result,
                    tags=["takeover", "subdomain", confidence],
                )
            )

        result.raw = {"checked": len(subdomains), "vulnerable": vulnerable, "target": target}
        self.logger.info(
            "Takeover check for %s complete — %d checked, %d potential findings",
            target,
            len(subdomains),
            len(vulnerable),
        )
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _check_subdomain(
        self,
        subdomain: str,
        fingerprints: List[Dict],
        dns_resolver: AsyncDNSResolver,
        http_client: AsyncHTTPClient,
        sem: asyncio.Semaphore,
    ) -> Optional[Dict[str, Any]]:
        """Check a single subdomain for takeover vulnerability.

        Args:
            subdomain: Subdomain to check.
            fingerprints: List of fingerprint dicts loaded from JSON.
            dns_resolver: Initialised :class:`AsyncDNSResolver` instance.
            http_client: Initialised :class:`AsyncHTTPClient` instance.
            sem: Semaphore controlling max concurrency.

        Returns:
            Dict with takeover info or ``None`` if no issue detected.
            Keys: subdomain, cname, service, fingerprint_matched,
            nxdomain, confidence, severity.
        """
        async with sem:
            try:
                cname_records = await dns_resolver.resolve(subdomain, "CNAME")
                if not cname_records:
                    return None

                cname = cname_records[0].rstrip(".")
                matched_fp = self._match_cname(cname, fingerprints)
                if matched_fp is None:
                    return None

                service = matched_fp.get("service", "Unknown")
                fp_strings: List[str] = matched_fp.get("fingerprints", [])

                nxdomain = await self._check_nxdomain(cname, dns_resolver)

                fp_matched: Optional[str] = None
                url = f"http://{subdomain}"
                fp_matched = await self._check_fingerprint_in_body(url, fp_strings, http_client)

                # Determine confidence
                if fp_matched and nxdomain:
                    confidence = "confirmed"
                elif fp_matched:
                    confidence = "high"
                elif nxdomain:
                    confidence = "medium"
                else:
                    confidence = "low"

                severity = _CONFIDENCE_SEVERITY.get(confidence, "medium")

                return {
                    "subdomain": subdomain,
                    "cname": cname,
                    "service": service,
                    "fingerprint_matched": fp_matched or "",
                    "nxdomain": nxdomain,
                    "confidence": confidence,
                    "severity": severity,
                }
            except Exception as exc:  # noqa: BLE001
                self.logger.debug("Error checking subdomain %s: %s", subdomain, exc)
                return None

    def _match_cname(self, cname: str, fingerprints: List[Dict]) -> Optional[Dict]:
        """Check if *cname* matches any fingerprint's ``cnames`` list.

        Supports wildcard patterns such as ``"*.github.io"`` which will match
        any host ending in ``.github.io``.

        Args:
            cname: Resolved CNAME value to check (trailing dot stripped).
            fingerprints: List of fingerprint dicts.

        Returns:
            Matching fingerprint dict, or ``None`` if no match.
        """
        cname_lower = cname.lower().rstrip(".")
        for fp in fingerprints:
            for pattern in fp.get("cnames", []):
                pattern_lower = pattern.lower().rstrip(".")
                if pattern_lower.startswith("*."):
                    suffix = pattern_lower[1:]  # e.g. ".github.io"
                    if cname_lower.endswith(suffix) or cname_lower == suffix.lstrip("."):
                        return fp
                else:
                    if cname_lower == pattern_lower:
                        return fp
        return None

    async def _check_nxdomain(self, cname: str, resolver: AsyncDNSResolver) -> bool:
        """Return ``True`` if *cname* resolves to NXDOMAIN.

        Queries for A and AAAA records; NXDOMAIN is indicated by empty results
        for both record types.

        Args:
            cname: CNAME target to check.
            resolver: Initialised :class:`AsyncDNSResolver` instance.

        Returns:
            ``True`` if no A or AAAA records are found.
        """
        try:
            a_records = await resolver.resolve(cname, "A")
            aaaa_records = await resolver.resolve(cname, "AAAA")
            return not a_records and not aaaa_records
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("NXDOMAIN check for %s failed: %s", cname, exc)
            return False

    async def _check_fingerprint_in_body(
        self,
        url: str,
        fingerprints: List[str],
        http_client: AsyncHTTPClient,
    ) -> Optional[str]:
        """Fetch *url* and check whether any fingerprint string appears in the body.

        Args:
            url: URL to fetch.
            fingerprints: List of fingerprint strings to look for.
            http_client: Initialised :class:`AsyncHTTPClient` instance.

        Returns:
            The first matched fingerprint string, or ``None`` if none matched
            or an error occurred.
        """
        if not fingerprints:
            return None
        try:
            resp = await http_client.get(url, allow_redirects=True)
            body: str = resp.get("body", "") or ""
            for fp_str in fingerprints:
                if fp_str and fp_str in body:
                    return fp_str
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("HTTP fingerprint check for %s failed: %s", url, exc)
        return None

    @classmethod
    def _load_fingerprints(cls, data_path: Optional[str] = None) -> List[Dict[str, Any]]:
        """Load takeover fingerprints from ``takeover_fingerprints.json``.

        Args:
            data_path: Optional explicit path to the JSON file.  Defaults to
                the bundled ``godrecon/data/takeover_fingerprints.json``.

        Returns:
            List of fingerprint dicts, or an empty list on error.
        """
        if data_path is None:
            path = Path(__file__).parent.parent.parent / "data" / "takeover_fingerprints.json"
        else:
            path = Path(data_path)

        try:
            with path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, list):
                return data
            logger.warning("Unexpected fingerprints format in %s", path)
            return []
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to load takeover fingerprints from %s: %s", path, exc)
            return []
