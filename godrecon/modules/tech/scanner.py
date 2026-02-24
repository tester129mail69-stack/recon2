"""Technology detection module entry point for GODRECON.

Auto-discovered by the :class:`~godrecon.core.engine.ScanEngine` via the
``scanner`` sub-module convention.  Orchestrates technology fingerprinting,
favicon hash analysis, and JARM TLS fingerprinting.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult
from godrecon.modules.tech.favicon import FaviconHasher
from godrecon.modules.tech.fingerprint import TechFingerprinter
from godrecon.modules.tech.jarm import JARMFingerprinter
from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)


class TechDetectionModule(BaseModule):
    """Technology detection: fingerprinting, favicon hash, and JARM.

    Probes HTTP/HTTPS services on the target and identifies technologies,
    frameworks, CDNs, WAFs, analytics, and cloud providers.
    """

    name = "tech"
    description = "Technology fingerprinting: CMS, frameworks, WAF, CDN, analytics"
    author = "GODRECON Team"
    version = "1.0.0"
    category = "tech"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        """Run technology detection for *target*.

        Args:
            target: Domain or IP to analyse.
            config: Scan configuration.

        Returns:
            :class:`ModuleResult` containing technology findings.
        """
        result = ModuleResult(module_name=self.name, target=target)
        tech_cfg = config.tech_detection

        # Probe the main HTTP and HTTPS URLs
        urls_to_check = [f"https://{target}", f"http://{target}"]
        all_detections: List[Dict[str, Any]] = []

        async with AsyncHTTPClient(
            timeout=config.general.timeout,
            user_agents=config.general.user_agents,
            proxy=config.general.proxy,
            verify_ssl=False,
            retries=1,
        ) as http:
            # Fingerprint each URL
            fingerprint_tasks = [
                asyncio.create_task(
                    self._run_safe(
                        "fingerprint",
                        self._fingerprint_url(http, url),
                    )
                )
                for url in urls_to_check
            ]

            favicon_tasks = []
            if tech_cfg.favicon_hash:
                for url in urls_to_check:
                    favicon_hasher = FaviconHasher(http)
                    favicon_tasks.append(
                        asyncio.create_task(
                            self._run_safe(
                                "favicon",
                                favicon_hasher.hash_favicon(url),
                            )
                        )
                    )

            fingerprint_results = await asyncio.gather(*fingerprint_tasks)
            favicon_results = await asyncio.gather(*favicon_tasks) if favicon_tasks else []

        # JARM fingerprinting (uses raw sockets, not HTTP client)
        jarm_result: Any = None
        if tech_cfg.jarm:
            jarm_fp = JARMFingerprinter(timeout=10.0)
            jarm_result = await self._run_safe(
                "jarm", jarm_fp.fingerprint(target, 443)
            )

        # Consolidate fingerprint detections
        seen_techs: set = set()
        for fp_result in fingerprint_results:
            if not isinstance(fp_result, list):
                continue
            for detection in fp_result:
                name_key = detection.get("name", "")
                if name_key and name_key not in seen_techs:
                    seen_techs.add(name_key)
                    all_detections.append(detection)
                    self._add_tech_finding(result, detection)

        # Favicon findings
        for fav_result in favicon_results:
            if isinstance(fav_result, dict) and fav_result.get("found"):
                self._add_favicon_finding(result, fav_result)

        # JARM findings
        if jarm_result and isinstance(jarm_result, dict) and jarm_result.get("jarm_hash"):
            self._add_jarm_finding(result, jarm_result)

        result.raw = {
            "technologies": all_detections,
            "favicon": next(
                (r for r in favicon_results if isinstance(r, dict) and r),
                {},
            ),
            "jarm": jarm_result or {},
        }
        logger.info(
            "Tech detection for %s complete — %d technologies, %d findings",
            target,
            len(all_detections),
            len(result.findings),
        )
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _fingerprint_url(
        self, http: AsyncHTTPClient, url: str
    ) -> List[Dict[str, Any]]:
        """Fetch *url* and run technology fingerprinting.

        Args:
            http: HTTP client.
            url: URL to probe.

        Returns:
            List of technology detection dicts.
        """
        try:
            resp = await http.get(url, allow_redirects=True)
            headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
            body = resp.get("body", "")
            cookies = headers.get("set-cookie", "")
            fp = TechFingerprinter(headers=headers, body=body, cookies=cookies, url=url)
            return fp.fingerprint()
        except Exception as exc:  # noqa: BLE001
            logger.debug("Fingerprint probe failed for %s: %s", url, exc)
            return []

    # ------------------------------------------------------------------
    # Finding builders
    # ------------------------------------------------------------------

    @staticmethod
    def _add_tech_finding(result: ModuleResult, detection: Dict[str, Any]) -> None:
        """Add a technology detection finding.

        Args:
            result: Module result to append to.
            detection: Technology detection dict.
        """
        name = detection.get("name", "Unknown")
        category = detection.get("category", "unknown")
        version = detection.get("version", "")
        confidence = detection.get("confidence", 0)

        version_str = f" v{version}" if version else ""
        desc = (
            f"Detected {category}: {name}{version_str} "
            f"(confidence: {confidence}%)"
        )
        if detection.get("website"):
            desc += f"\nWebsite: {detection['website']}"

        severity = "info"
        # WAF detection is informational but useful
        if category == "waf":
            severity = "info"

        result.findings.append(
            Finding(
                title=f"Technology Detected: {name}{version_str}",
                description=desc,
                severity=severity,
                data=detection,
                tags=["tech", category, name.lower().replace(" ", "-")],
            )
        )

    @staticmethod
    def _add_favicon_finding(result: ModuleResult, fav: Dict[str, Any]) -> None:
        """Add a favicon hash finding.

        Args:
            result: Module result to append to.
            fav: Favicon hash result dict.
        """
        tech = fav.get("technology")
        mmh3_hash = fav.get("hash")
        url = fav.get("url", "")

        if tech:
            result.findings.append(
                Finding(
                    title=f"Favicon Hash Identifies: {tech}",
                    description=(
                        f"Favicon MMH3 hash {mmh3_hash} matches known signature for {tech}. "
                        f"Favicon URL: {url}"
                    ),
                    severity="info",
                    data=fav,
                    tags=["tech", "favicon", "fingerprint"],
                )
            )
        else:
            result.findings.append(
                Finding(
                    title=f"Favicon Hash: {mmh3_hash}",
                    description=(
                        f"Favicon found with MMH3 hash {mmh3_hash}. "
                        "No matching technology signature in the database."
                    ),
                    severity="info",
                    data=fav,
                    tags=["tech", "favicon"],
                )
            )

    @staticmethod
    def _add_jarm_finding(result: ModuleResult, jarm: Dict[str, Any]) -> None:
        """Add a JARM fingerprint finding.

        Args:
            result: Module result to append to.
            jarm: JARM fingerprint result dict.
        """
        tech = jarm.get("technology")
        jarm_hash = jarm.get("jarm_hash", "")
        host = jarm.get("host", "")
        port = jarm.get("port", 443)

        if tech:
            severity = "high" if any(
                kw in tech.lower()
                for kw in ("c2", "cobalt", "metasploit", "rat", "asyncrat", "sliver", "brute")
            ) else "info"
            result.findings.append(
                Finding(
                    title=f"JARM Fingerprint Matches: {tech}",
                    description=(
                        f"TLS JARM fingerprint for {host}:{port} matches known signature for {tech}. "
                        f"JARM hash: {jarm_hash}"
                    ),
                    severity=severity,
                    data=jarm,
                    tags=["tech", "jarm", "tls", "fingerprint"],
                )
            )
        else:
            result.findings.append(
                Finding(
                    title=f"JARM Fingerprint: {jarm_hash[:16]}...",
                    description=(
                        f"TLS JARM fingerprint for {host}:{port}: {jarm_hash}"
                    ),
                    severity="info",
                    data=jarm,
                    tags=["tech", "jarm", "tls"],
                )
            )

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    async def _run_safe(name: str, coro: Any) -> Any:
        """Await *coro*, returning ``None`` on any exception.

        Args:
            name: Human-readable sub-check name.
            coro: Coroutine to run.

        Returns:
            Result or ``None``.
        """
        try:
            return await coro
        except Exception as exc:  # noqa: BLE001
            logger.warning("Tech sub-check '%s' failed: %s", name, exc)
            return None
