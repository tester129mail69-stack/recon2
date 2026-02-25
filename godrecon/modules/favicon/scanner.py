"""Favicon hash fingerprinting for technology detection."""
from __future__ import annotations

import base64
import hashlib
from typing import Any, Dict, List, Optional

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# Known favicon hashes (mmh3 hash → technology name)
# Shodan-style favicon hashes: mmh3(base64_encoded_favicon_data)
_FAVICON_DB: Dict[int, str] = {
    # Web Servers
    -1506543714: "Apache HTTP Server",
    -1066315155: "Nginx",
    272576924: "Microsoft IIS",
    -1604602729: "LiteSpeed",
    # CMS
    -1074136313: "WordPress",
    1485053081: "Drupal",
    -1604985077: "Joomla",
    1230984951: "Magento",
    # Frameworks / Platforms
    -1448704800: "Django",
    -1526633474: "Laravel",
    1388090952: "Spring Boot",
    -397628989: "Ruby on Rails",
    # Panels / Admin Interfaces
    -1268770289: "cPanel",
    1942296349: "Plesk",
    -2052955748: "phpMyAdmin",
    -1420058154: "Webmin",
    81586312: "Jenkins",
    -1148163471: "Grafana",
    -1250765965: "Kibana",
    # Networking Devices
    1642928819: "Cisco Router/Switch",
    -1231174641: "Fortinet/FortiGate",
    116357906: "Palo Alto Networks",
    -1567000762: "SonicWall",
    -862805402: "pfSense",
    # Cloud Defaults
    -1284116359: "AWS Default Page",
    -1352422998: "Azure Default Page",
    -2079585043: "GCP Default Page",
    # Other common services
    113675: "Tomcat",
    -1142337945: "GitLab",
    116559052: "Bitbucket",
    -928651723: "Confluence",
    1957226820: "JIRA",
    -1380263716: "Prometheus",
    -1529891654: "RabbitMQ",
    -1928892614: "Elasticsearch",
    1496225065: "Portainer",
    -784069918: "Traefik",
    -1088498891: "Keycloak",
    945816483: "Rancher",
    -1574505965: "Vault (HashiCorp)",
    1499057227: "Consul (HashiCorp)",
    -1484472714: "Netdata",
    -1580288022: "Zabbix",
    895939870: "Nagios",
    -388617256: "OpenVPN",
    1073741835: "pfBlockerNG",
}

_FAVICON_PATHS = ["/favicon.ico", "/favicon.png", "/apple-touch-icon.png"]


class FaviconModule(BaseModule):
    """Favicon hash fingerprinting for technology detection."""

    name = "favicon"
    description = "Favicon hash fingerprinting for technology detection"
    category = "recon"
    version = "1.0.0"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        """Fetch favicon and compute hash for fingerprinting."""
        result = ModuleResult(module_name=self.name, target=target)
        timeout = getattr(getattr(config, "general", None), "timeout", 10) or 10
        base_url = f"https://{target}" if not target.startswith("http") else target

        for favicon_path in _FAVICON_PATHS:
            url = base_url.rstrip("/") + favicon_path
            favicon_data = await self._run_safe(
                f"favicon:{favicon_path}",
                self._fetch_favicon(url, timeout),
            )
            if favicon_data:
                mmh3_hash, md5_hash, technology = self._compute_hashes(favicon_data)

                severity = "info"
                description_parts = [
                    f"URL: {url}",
                    f"MMH3 Hash (Shodan): {mmh3_hash}",
                    f"MD5 Hash: {md5_hash}",
                    f"Size: {len(favicon_data)} bytes",
                ]
                if technology:
                    description_parts.append(f"Identified Technology: {technology}")
                    severity = "low"

                result.findings.append(Finding(
                    title=f"Favicon Found: {url}" + (f" — {technology}" if technology else ""),
                    description="\n".join(description_parts),
                    severity=severity,
                    data={
                        "url": url,
                        "mmh3_hash": mmh3_hash,
                        "md5_hash": md5_hash,
                        "technology": technology,
                        "size_bytes": len(favicon_data),
                    },
                    tags=["favicon", "fingerprint", "recon"] + ([technology.lower().replace(" ", "-")] if technology else []),
                ))

                result.raw = {
                    "favicon_url": url,
                    "mmh3_hash": mmh3_hash,
                    "md5_hash": md5_hash,
                    "technology": technology,
                }
                break  # Found favicon, stop checking other paths

        if not result.findings:
            result.raw = {"favicon_found": False}

        logger.info(
            "Favicon scan for %s: found=%s tech=%s",
            target,
            bool(result.findings),
            result.raw.get("technology"),
        )
        return result

    @staticmethod
    async def _fetch_favicon(url: str, timeout: int = 10) -> Optional[bytes]:
        """Fetch favicon bytes from URL."""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    ssl=False,
                    allow_redirects=True,
                ) as resp:
                    if resp.status != 200:
                        return None
                    data = await resp.read()
                    if len(data) < 10:
                        return None
                    return data
        except Exception as exc:
            logger.debug("Favicon fetch error for %s: %s", url, exc)
            return None

    @staticmethod
    def _compute_hashes(data: bytes) -> tuple:
        """Compute mmh3 and MD5 hashes of favicon data.

        Returns (mmh3_hash, md5_hash, technology_name_or_None).
        """
        try:
            import mmh3
            # Shodan-style: mmh3 of base64-encoded data
            b64 = base64.encodebytes(data).decode()
            mmh3_hash = mmh3.hash(b64)
        except ImportError:
            logger.warning("mmh3 not installed — using fallback hash")
            mmh3_hash = hash(data) & 0xFFFFFFFF  # fallback

        md5_hash = hashlib.md5(data).hexdigest()  # noqa: S324
        technology = _FAVICON_DB.get(mmh3_hash)
        return mmh3_hash, md5_hash, technology

    @staticmethod
    async def _run_safe(name: str, coro: Any) -> Any:
        """Run a coroutine safely."""
        try:
            return await coro
        except Exception as exc:
            logger.warning("Favicon sub-check '%s' failed: %s", name, exc)
            return None
