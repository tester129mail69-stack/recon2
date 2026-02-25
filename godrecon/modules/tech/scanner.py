"""Technology detection module entry point for GODRECON.

KEY IMPROVEMENT: Detected technologies are published to a shared store so
PatternMatcher and CVELookup can consume them automatically without any
engine refactor — just call get_detected_tech(target).
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult
from godrecon.modules.tech.favicon import FaviconHasher
from godrecon.modules.tech.fingerprint import TechFingerprinter
from godrecon.modules.tech.jarm import JARMFingerprinter
from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_SHARED_TECH_STORE: Dict[str, List[Dict[str, Any]]] = {}


def get_detected_tech(target: str) -> List[Dict[str, Any]]:
    """Retrieve detected technologies for a target (called by vuln modules)."""
    return _SHARED_TECH_STORE.get(target, [])


def _store_detected_tech(target: str, techs: List[Dict[str, Any]]) -> None:
    _SHARED_TECH_STORE[target] = techs
    logger.debug("Stored %d detected technologies for '%s' in shared store", len(techs), target)


class TechDetectionModule(BaseModule):
    name = "tech"
    description = "Technology fingerprinting: CMS, frameworks, WAF, CDN, analytics"
    author = "GODRECON Team"
    version = "1.1.0"
    category = "tech"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=target)
        tech_cfg = config.tech_detection
        urls_to_check = [f"https://{target}", f"http://{target}"]
        all_detections: List[Dict[str, Any]] = []

        async with AsyncHTTPClient(
            timeout=config.general.timeout,
            user_agents=config.general.user_agents,
            proxy=config.general.proxy,
            verify_ssl=False,
            retries=1,
        ) as http:
            fingerprint_tasks = [
                asyncio.create_task(self._run_safe("fingerprint", self._fingerprint_url(http, url)))
                for url in urls_to_check
            ]
            favicon_tasks: List[asyncio.Task] = []
            if getattr(tech_cfg, "favicon_hash", True):
                for url in urls_to_check:
                    favicon_hasher = FaviconHasher(http)
                    favicon_tasks.append(
                        asyncio.create_task(self._run_safe("favicon", favicon_hasher.hash_favicon(url)))
                    )
            fingerprint_results = await asyncio.gather(*fingerprint_tasks)
            favicon_results = await asyncio.gather(*favicon_tasks) if favicon_tasks else []

        jarm_result: Optional[Dict[str, Any]] = None
        if getattr(tech_cfg, "jarm", False):
            jarm_fp = JARMFingerprinter(timeout=10.0)
            jarm_result = await self._run_safe("jarm", jarm_fp.fingerprint(target, 443))

        seen_techs: set = set()
        for fp_result in fingerprint_results:
            if not isinstance(fp_result, list):
                continue
            for detection in fp_result:
                name_key = detection.get("name", "")
                if not name_key:
                    continue
                if name_key not in seen_techs:
                    seen_techs.add(name_key)
                    all_detections.append(detection)
                    self._add_tech_finding(result, detection)
                else:
                    for existing in all_detections:
                        if existing["name"] == name_key:
                            if not existing.get("version") and detection.get("version"):
                                existing["version"] = detection["version"]
                            if detection.get("confidence", 0) > existing.get("confidence", 0):
                                existing["confidence"] = detection["confidence"]
                            break

        # Publish for inter-module sharing
        _store_detected_tech(target, all_detections)

        for fav_result in favicon_results:
            if isinstance(fav_result, dict) and fav_result.get("found"):
                self._add_favicon_finding(result, fav_result)

        if jarm_result and isinstance(jarm_result, dict) and jarm_result.get("jarm_hash"):
            self._add_jarm_finding(result, jarm_result)

        result.raw = {
            "technologies": all_detections,
            "favicon": next((r for r in favicon_results if isinstance(r, dict) and r), {}),
            "jarm": jarm_result or {},
        }

        logger.info("Tech detection for %s complete — %d technologies, %d findings", target, len(all_detections), len(result.findings))
        if all_detections:
            tech_summary = ", ".join(
                f"{t['name']}" + (f" v{t['version']}" if t.get("version") else "")
                for t in all_detections[:10]
            )
            logger.info("Detected on %s: %s", target, tech_summary)

        return result

    async def _fingerprint_url(self, http: AsyncHTTPClient, url: str) -> List[Dict[str, Any]]:
        try:
            resp = await http.get(url, allow_redirects=True)
            if not resp:
                return []
            headers = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
            body = resp.get("body") or ""
            cookies = headers.get("set-cookie", "")
            fp = TechFingerprinter(headers=headers, body=body, cookies=cookies, url=url)
            detections = fp.fingerprint()
            logger.debug("Fingerprinted %s — %d technologies found", url, len(detections))
            return detections
        except Exception as exc:
            logger.debug("Fingerprint probe failed for %s: %s", url, exc)
            return []

    @staticmethod
    def _add_tech_finding(result: ModuleResult, detection: Dict[str, Any]) -> None:
        name = detection.get("name", "Unknown")
        category = detection.get("category", "unknown")
        version = detection.get("version", "")
        confidence = detection.get("confidence", 0)
        version_str = f" v{version}" if version else ""
        desc = f"Detected {category}: {name}{version_str} (confidence: {confidence}%)"
        if detection.get("website"):
            desc += f"\nWebsite: {detection['website']}"
        result.findings.append(Finding(
            title=f"Technology Detected: {name}{version_str}",
            description=desc,
            severity="info",
            data=detection,
            tags=["tech", category, name.lower().replace(" ", "-")],
        ))

    @staticmethod
    def _add_favicon_finding(result: ModuleResult, fav: Dict[str, Any]) -> None:
        tech = fav.get("technology")
        mmh3_hash = fav.get("hash")
        url = fav.get("url", "")
        if tech:
            result.findings.append(Finding(
                title=f"Favicon Hash Identifies: {tech}",
                description=f"Favicon MMH3 hash {mmh3_hash} matches known signature for {tech}. Favicon URL: {url}",
                severity="info",
                data=fav,
                tags=["tech", "favicon", "fingerprint"],
            ))
        else:
            result.findings.append(Finding(
                title=f"Favicon Hash: {mmh3_hash}",
                description=f"Favicon found with MMH3 hash {mmh3_hash}. No matching technology signature.",
                severity="info",
                data=fav,
                tags=["tech", "favicon"],
            ))

    @staticmethod
    def _add_jarm_finding(result: ModuleResult, jarm: Dict[str, Any]) -> None:
        tech = jarm.get("technology")
        jarm_hash = jarm.get("jarm_hash", "")
        host = jarm.get("host", "")
        port = jarm.get("port", 443)
        if tech:
            severity = "high" if any(kw in tech.lower() for kw in ("c2", "cobalt", "metasploit", "rat", "asyncrat", "sliver")) else "info"
            result.findings.append(Finding(
                title=f"JARM Fingerprint Matches: {tech}",
                description=f"TLS JARM fingerprint for {host}:{port} matches known signature for {tech}. JARM hash: {jarm_hash}",
                severity=severity,
                data=jarm,
                tags=["tech", "jarm", "tls", "fingerprint"],
            ))
        else:
            result.findings.append(Finding(
                title=f"JARM Fingerprint: {jarm_hash[:16]}...",
                description=f"TLS JARM fingerprint for {host}:{port}: {jarm_hash}",
                severity="info",
                data=jarm,
                tags=["tech", "jarm", "tls"],
            ))

    @staticmethod
    async def _run_safe(name: str, coro: Any) -> Any:
        try:
            return await coro
        except Exception as exc:
            logger.warning("Tech sub-check '%s' failed: %s", name, exc)
            return None
