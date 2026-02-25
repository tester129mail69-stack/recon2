"""Web Application Firewall (WAF) detection module for GODRECON."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# WAF signatures: list of (waf_name, header_key, header_value_pattern, cookie_pattern, confidence)
_WAF_SIGNATURES: List[Dict[str, Any]] = [
    {"name": "CloudFlare", "headers": {"cf-ray": None, "server": "cloudflare"}, "cookies": ["__cfduid", "cf_clearance"], "confidence": "high"},
    {"name": "AWS WAF/CloudFront", "headers": {"x-amz-cf-id": None, "x-amzn-requestid": None}, "cookies": [], "confidence": "high"},
    {"name": "Akamai", "headers": {"x-akamai-transformed": None, "akamai-origin-hop": None}, "cookies": [], "confidence": "high"},
    {"name": "Imperva/Incapsula", "headers": {"x-iinfo": None}, "cookies": ["incap_ses_", "visid_incap_"], "confidence": "high"},
    {"name": "Sucuri", "headers": {"x-sucuri-id": None, "x-sucuri-cache": None}, "cookies": [], "confidence": "high"},
    {"name": "F5 BIG-IP", "headers": {"x-cnection": None}, "cookies": ["BigIP", "BIGipServer"], "confidence": "medium"},
    {"name": "Barracuda", "headers": {}, "cookies": ["barra_counter_session"], "confidence": "medium"},
    {"name": "Fortinet/FortiWeb", "headers": {}, "cookies": ["FORTIWAFSID"], "confidence": "high"},
    {"name": "Citrix NetScaler", "headers": {"via": "NS-CACHE"}, "cookies": ["ns_af", "NSC_"], "confidence": "medium"},
    {"name": "ModSecurity", "headers": {"server": "Apache"}, "cookies": [], "confidence": "low"},
]

_ATTACK_PAYLOAD = "/?test=<script>alert(1)</script>&cmd=../etc/passwd"


class WAFDetectorModule(BaseModule):
    """Web Application Firewall detection module."""

    name = "waf"
    description = "Web Application Firewall detection"
    category = "http"
    version = "1.0.0"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        """Detect WAF presence for the target domain."""
        result = ModuleResult(module_name=self.name, target=target)
        timeout = getattr(getattr(config, "general", None), "timeout", 10) or 10

        base_url = f"https://{target}" if not target.startswith("http") else target

        detected: List[Dict[str, Any]] = []

        # Step 1: Normal request — check headers/cookies for WAF signatures
        normal_resp = await self._run_safe("normal_request", self._fetch(base_url, timeout))
        if normal_resp:
            waf = self._check_signatures(normal_resp)
            if waf:
                waf["detection_method"] = "header/cookie signature"
                detected.append(waf)

        # Step 2: Attack payload — check if blocked
        attack_url = base_url.rstrip("/") + _ATTACK_PAYLOAD
        attack_resp = await self._run_safe("attack_request", self._fetch(attack_url, timeout))
        if attack_resp and attack_resp.get("status") in (403, 406, 429):
            if not detected:
                detected.append({
                    "name": "Unknown WAF",
                    "confidence": "low",
                    "detection_method": "blocked attack payload",
                    "evidence": f"Status {attack_resp['status']} on attack payload",
                })
            else:
                detected[0]["detection_method"] += " + blocked attack payload"
                detected[0]["confidence"] = "high"

        if detected:
            for waf_info in detected:
                result.findings.append(Finding(
                    title=f"WAF Detected: {waf_info['name']}",
                    description=(
                        f"WAF: {waf_info['name']}\n"
                        f"Confidence: {waf_info['confidence']}\n"
                        f"Detection Method: {waf_info.get('detection_method', '')}\n"
                        f"Evidence: {waf_info.get('evidence', '')}"
                    ),
                    severity="info",
                    data=waf_info,
                    tags=["waf", "detection", waf_info["name"].lower().replace("/", "-").replace(" ", "-")],
                ))
        else:
            result.findings.append(Finding(
                title=f"No WAF Detected: {target}",
                description="No Web Application Firewall signatures detected.",
                severity="info",
                data={"waf_detected": False},
                tags=["waf", "detection"],
            ))

        result.raw = {"waf_detected": bool(detected), "detections": detected}
        logger.info("WAF detection for %s: %s", target, detected[0]["name"] if detected else "none")
        return result

    @staticmethod
    async def _fetch(url: str, timeout: int = 10) -> Optional[Dict[str, Any]]:
        """Fetch a URL and return status + headers + cookies."""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    allow_redirects=True,
                    ssl=False,
                ) as resp:
                    headers = dict(resp.headers)
                    cookies = {k: v.value for k, v in resp.cookies.items()}
                    return {
                        "status": resp.status,
                        "headers": {k.lower(): v.lower() for k, v in headers.items()},
                        "cookies": {k.lower(): v.lower() for k, v in cookies.items()},
                    }
        except Exception as exc:
            logger.debug("WAF fetch error for %s: %s", url, exc)
            return None

    @staticmethod
    def _check_signatures(response: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check response against WAF signature database."""
        headers = response.get("headers", {})
        cookies = response.get("cookies", {})
        cookie_str = " ".join(cookies.keys())

        for sig in _WAF_SIGNATURES:
            matched_evidence = []

            # Check headers
            for hdr_key, hdr_val in sig["headers"].items():
                if hdr_key in headers:
                    if hdr_val is None or hdr_val.lower() in headers[hdr_key]:
                        matched_evidence.append(f"header:{hdr_key}")

            # Check cookies
            for cookie_pattern in sig["cookies"]:
                if cookie_pattern.lower() in cookie_str:
                    matched_evidence.append(f"cookie:{cookie_pattern}")

            if matched_evidence:
                return {
                    "name": sig["name"],
                    "confidence": sig["confidence"],
                    "evidence": ", ".join(matched_evidence),
                }

        return None

    @staticmethod
    async def _run_safe(name: str, coro: Any) -> Any:
        """Run a coroutine safely, returning None on error."""
        try:
            return await coro
        except Exception as exc:
            logger.warning("WAF sub-check '%s' failed: %s", name, exc)
            return None
