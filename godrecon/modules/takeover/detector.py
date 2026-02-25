"""Subdomain takeover detection module for GODRECON.

Automatically pulls all discovered subdomains from the shared store and
checks every single one for takeover vulnerabilities.

Detection method:
  1. Resolve CNAME for each subdomain
  2. Match CNAME against 100+ known-vulnerable service fingerprints
  3. Check if CNAME target resolves to NXDOMAIN (unclaimed resource)
  4. Fetch HTTP body and match fingerprint strings
  5. Confidence: confirmed (NXDOMAIN + fingerprint), high (fingerprint only),
     medium (NXDOMAIN only), low (CNAME match only)
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult
from godrecon.utils.dns_resolver import AsyncDNSResolver
from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_CONFIDENCE_SEVERITY: Dict[str, str] = {
    "confirmed": "critical",
    "high":      "critical",
    "medium":    "high",
    "low":       "medium",
}

_SUBDOMAIN_WAIT_TIMEOUT  = 60.0
_SUBDOMAIN_WAIT_INTERVAL = 1.0
_CHECK_CONCURRENCY       = 30


class TakeoverDetectorModule(BaseModule):
    """Subdomain takeover vulnerability detection.

    Checks every subdomain discovered by the subdomain module against
    100+ known-vulnerable service fingerprints.
    """

    name        = "takeover"
    description = "Subdomain takeover detection — auto-scans all discovered subdomains"
    category    = "takeover"
    version     = "2.0.0"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        result      = ModuleResult(module_name=self.name, target=target)
        takeover_cfg = getattr(config, "takeover", None)
        enabled     = getattr(takeover_cfg, "enabled", True)

        if not enabled:
            result.raw = {"checked": 0, "vulnerable": [], "target": target}
            return result

        fingerprints = self._load_fingerprints()
        if not fingerprints:
            logger.warning("No takeover fingerprints loaded — skipping module.")
            result.raw = {"checked": 0, "vulnerable": [], "target": target}
            return result

        # ── Pull all discovered subdomains from shared store ────────────
        subdomains = await self._wait_for_subdomains(target)
        logger.info(
            "Takeover check starting — %d subdomains to check for %s",
            len(subdomains), target,
        )

        # ── Run checks ──────────────────────────────────────────────────
        sem       = asyncio.Semaphore(_CHECK_CONCURRENCY)
        vulnerable: List[Dict[str, Any]] = []

        async with AsyncDNSResolver() as dns_resolver:
            async with AsyncHTTPClient(
                timeout=10,
                max_connections=_CHECK_CONCURRENCY,
                verify_ssl=False,
                retries=1,
            ) as http_client:

                async def _check_one(sub: str) -> Optional[Dict[str, Any]]:
                    async with sem:
                        return await self._check_subdomain(
                            sub, fingerprints, dns_resolver, http_client
                        )

                t_start  = time.monotonic()
                results  = await asyncio.gather(
                    *[_check_one(s) for s in subdomains],
                    return_exceptions=True,
                )
                elapsed  = time.monotonic() - t_start

        # ── Build findings ───────────────────────────────────────────────
        for sub, res in zip(subdomains, results):
            if isinstance(res, Exception):
                logger.debug("Takeover check error for %s: %s", sub, res)
                continue
            if res is None:
                continue

            vulnerable.append(res)
            confidence  = res.get("confidence", "low")
            service     = res.get("service", "Unknown")
            severity    = _CONFIDENCE_SEVERITY.get(confidence, "medium")
            cname       = res.get("cname", "")
            fp_matched  = res.get("fingerprint_matched", "")
            nxdomain    = res.get("nxdomain", False)
            docs        = res.get("documentation", "")

            desc_lines = [
                f"Subdomain:          {sub}",
                f"CNAME:              {cname}",
                f"Vulnerable Service: {service}",
                f"Confidence:         {confidence.upper()}",
                f"Severity:           {severity.upper()}",
            ]
            if fp_matched:
                desc_lines.append(f"Fingerprint:        {fp_matched!r}")
            if nxdomain:
                desc_lines.append("NXDOMAIN:           YES — CNAME target is unclaimed")
            if docs:
                desc_lines.append(f"Reference:          {docs}")

            desc_lines.append(
                "\nREMEDIATION: Remove the dangling CNAME DNS record immediately "
                "or re-claim the resource on the target service."
            )

            logger.info(
                "TAKEOVER [%s][%s] %s -> %s | NXDOMAIN:%s | fp:%r",
                severity.upper(),
                confidence.upper(),
                sub,
                service,
                nxdomain,
                fp_matched,
            )

            result.findings.append(
                Finding(
                    title=f"[{severity.upper()}] Subdomain Takeover: {sub} → {service}",
                    description="\n".join(desc_lines),
                    severity=severity,
                    data=res,
                    tags=["takeover", "subdomain", confidence, service.lower()],
                )
            )

        result.raw = {
            "target":          target,
            "checked":         len(subdomains),
            "vulnerable":      vulnerable,
            "vulnerable_count": len(vulnerable),
            "scan_time_s":     round(elapsed, 2),
        }

        logger.info(
            "Takeover scan complete for %s — %d checked, %d vulnerable, %.1fs",
            target, len(subdomains), len(vulnerable), elapsed,
        )
        return result

    # ──────────────────────────────────────────────────────────────────────
    # Subdomain store
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    async def _wait_for_subdomains(target: str) -> List[str]:
        """Wait for subdomain shared store then return all discovered subdomains."""
        try:
            from godrecon.modules.subdomains import get_discovered_subdomains
        except ImportError:
            logger.debug("Subdomain shared store unavailable — checking root only")
            return [target]

        deadline = time.monotonic() + _SUBDOMAIN_WAIT_TIMEOUT
        while time.monotonic() < deadline:
            subs = get_discovered_subdomains(target)
            if subs:
                # Always include root target
                all_subs = [target] + [s for s in subs if s != target]
                logger.info(
                    "Subdomain store ready — %d subdomains for takeover check",
                    len(all_subs),
                )
                return all_subs
            await asyncio.sleep(_SUBDOMAIN_WAIT_INTERVAL)

        logger.info(
            "Subdomain store timed out for %s — checking root only", target
        )
        return [target]

    # ──────────────────────────────────────────────────────────────────────
    # Core check logic
    # ──────────────────────────────────────────────────────────────────────

    async def _check_subdomain(
        self,
        subdomain: str,
        fingerprints: List[Dict],
        dns_resolver: AsyncDNSResolver,
        http_client: AsyncHTTPClient,
    ) -> Optional[Dict[str, Any]]:
        """Check a single subdomain for takeover vulnerability.

        Returns a result dict if vulnerable, None otherwise.
        """
        try:
            # Step 1: resolve CNAME
            cname_records = await dns_resolver.resolve(subdomain, "CNAME")
            if not cname_records:
                return None

            cname = cname_records[0].rstrip(".")

            # Step 2: match CNAME against fingerprint database
            matched_fp = self._match_cname(cname, fingerprints)
            if matched_fp is None:
                return None

            service     = matched_fp.get("service", "Unknown")
            fp_strings  = matched_fp.get("fingerprints", [])
            docs        = matched_fp.get("documentation", "")

            # Step 3: check if CNAME target is NXDOMAIN
            nxdomain = await self._check_nxdomain(cname, dns_resolver)

            # Step 4: check HTTP body for fingerprint strings
            fp_matched: Optional[str] = None
            for scheme in ("https", "http"):
                fp_matched = await self._check_fingerprint_in_body(
                    f"{scheme}://{subdomain}", fp_strings, http_client
                )
                if fp_matched:
                    break

            # Step 5: determine confidence
            if fp_matched and nxdomain:
                confidence = "confirmed"
            elif fp_matched:
                confidence = "high"
            elif nxdomain:
                confidence = "medium"
            else:
                # CNAME matches but no NXDOMAIN and no body fingerprint
                # — too low signal, skip to avoid false positives
                return None

            severity = _CONFIDENCE_SEVERITY.get(confidence, "medium")

            return {
                "subdomain":           subdomain,
                "cname":               cname,
                "service":             service,
                "fingerprint_matched": fp_matched or "",
                "nxdomain":            nxdomain,
                "confidence":          confidence,
                "severity":            severity,
                "documentation":       docs,
            }

        except Exception as exc:
            logger.debug("Error checking subdomain %s: %s", subdomain, exc)
            return None

    @staticmethod
    def _match_cname(cname: str, fingerprints: List[Dict]) -> Optional[Dict]:
        """Match CNAME against fingerprint database. Supports wildcard patterns."""
        cname_lower = cname.lower().rstrip(".")
        for fp in fingerprints:
            for pattern in fp.get("cnames", []):
                pattern_lower = pattern.lower().rstrip(".")
                if pattern_lower.startswith("*."):
                    suffix = pattern_lower[1:]
                    if cname_lower.endswith(suffix) or cname_lower == suffix.lstrip("."):
                        return fp
                else:
                    if cname_lower == pattern_lower:
                        return fp
        return None

    @staticmethod
    async def _check_nxdomain(cname: str, resolver: AsyncDNSResolver) -> bool:
        """Return True if CNAME target has no A or AAAA records."""
        try:
            a    = await resolver.resolve(cname, "A")
            aaaa = await resolver.resolve(cname, "AAAA")
            return not a and not aaaa
        except Exception as exc:
            logger.debug("NXDOMAIN check for %s failed: %s", cname, exc)
            return False

    @staticmethod
    async def _check_fingerprint_in_body(
        url: str,
        fingerprints: List[str],
        http_client: AsyncHTTPClient,
    ) -> Optional[str]:
        """Fetch URL and return first matching fingerprint string found in body."""
        # Skip empty fingerprint lists
        valid_fps = [f for f in fingerprints if f and f.strip()]
        if not valid_fps:
            return None
        try:
            resp = await http_client.get(url, allow_redirects=True)
            body: str = resp.get("body", "") or ""
            for fp_str in valid_fps:
                if fp_str in body:
                    return fp_str
        except Exception as exc:
            logger.debug("HTTP fingerprint check for %s failed: %s", url, exc)
        return None

    @classmethod
    def _load_fingerprints(cls, data_path: Optional[str] = None) -> List[Dict[str, Any]]:
        """Load takeover fingerprints from takeover_fingerprints.json."""
        if data_path is None:
            path = Path(__file__).parent.parent.parent / "data" / "takeover_fingerprints.json"
        else:
            path = Path(data_path)

        try:
            with path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, list):
                logger.info("Loaded %d takeover fingerprints from %s", len(data), path)
                return data
            logger.warning("Unexpected fingerprints format in %s", path)
            return []
        except Exception as exc:
            logger.warning("Failed to load takeover fingerprints from %s: %s", path, exc)
            return []
