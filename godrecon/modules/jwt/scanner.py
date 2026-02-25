"""JWT token vulnerability detection module for GODRECON."""
from __future__ import annotations

import base64
import json
import re
from typing import Any, Dict, List, Optional, Tuple

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# Pattern to find JWTs in text (base64url header.payload.signature)
_JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")

_SENSITIVE_PAYLOAD_KEYS = {"password", "passwd", "secret", "key", "token", "ssn", "credit_card", "cvv", "pin"}


class JWTModule(BaseModule):
    """JWT token vulnerability detection."""

    name = "jwt"
    description = "JWT token vulnerability detection"
    category = "vulns"
    version = "1.0.0"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        """Collect JWTs from target responses and check for vulnerabilities."""
        result = ModuleResult(module_name=self.name, target=target)
        timeout = getattr(getattr(config, "general", None), "timeout", 10) or 10
        base_url = f"https://{target}" if not target.startswith("http") else target

        jwts = await self._collect_jwts(base_url, timeout)
        if not jwts:
            result.raw = {"jwts_found": 0, "vulnerabilities": []}
            return result

        all_vulns: List[Dict[str, Any]] = []
        for jwt_str in jwts:
            vulns = self._analyze_jwt(jwt_str)
            for vuln in vulns:
                all_vulns.append(vuln)
                result.findings.append(Finding(
                    title=f"JWT Vulnerability: {vuln['type']}",
                    description=(
                        f"Vulnerability: {vuln['type']}\n"
                        f"Severity: {vuln['severity']}\n"
                        f"Detail: {vuln['detail']}\n"
                        f"Remediation: {vuln.get('remediation', '')}"
                    ),
                    severity=vuln["severity"],
                    data={k: v for k, v in vuln.items() if k != "jwt"},
                    tags=["jwt", "vulnerability", vuln["type"].lower().replace(" ", "_")],
                ))

        result.raw = {"jwts_found": len(jwts), "vulnerabilities": all_vulns}
        logger.info("JWT scan for %s: %d JWTs found, %d vulnerabilities", target, len(jwts), len(all_vulns))
        return result

    async def _collect_jwts(self, url: str, timeout: int = 10) -> List[str]:
        """Collect JWT tokens from target HTTP responses."""
        jwts: List[str] = []
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    ssl=False,
                    allow_redirects=True,
                ) as resp:
                    # Check headers
                    auth_header = resp.headers.get("Authorization", "")
                    if auth_header.startswith("Bearer "):
                        token = auth_header[7:]
                        if _JWT_PATTERN.match(token):
                            jwts.append(token)

                    # Check cookies
                    for cookie_name, cookie in resp.cookies.items():
                        if _JWT_PATTERN.match(cookie.value):
                            jwts.append(cookie.value)

                    # Check body
                    body = await resp.text()
                    found_in_body = _JWT_PATTERN.findall(body)
                    jwts.extend(found_in_body[:5])  # limit to 5 from body

        except Exception as exc:
            logger.debug("JWT collection error for %s: %s", url, exc)

        # Deduplicate
        seen: set = set()
        unique = []
        for jwt in jwts:
            if jwt not in seen:
                seen.add(jwt)
                unique.append(jwt)
        return unique

    @classmethod
    def _analyze_jwt(cls, jwt_str: str) -> List[Dict[str, Any]]:
        """Analyze a JWT for vulnerabilities."""
        vulns: List[Dict[str, Any]] = []
        header, payload = cls._decode_jwt(jwt_str)
        if header is None:
            return vulns

        alg = header.get("alg", "")

        # Check alg:none
        if alg.lower() == "none":
            vulns.append({
                "type": "Algorithm None Attack",
                "severity": "critical",
                "detail": "JWT uses 'alg: none' which disables signature verification.",
                "remediation": "Reject JWTs with alg:none. Always verify signatures.",
                "jwt_header": header,
            })

        # Check missing exp
        if payload is not None and "exp" not in payload:
            vulns.append({
                "type": "Missing Expiration Claim",
                "severity": "medium",
                "detail": "JWT has no 'exp' claim — it never expires.",
                "remediation": "Add an expiration claim to all JWTs.",
                "jwt_header": header,
            })

        # Check weak/missing iss
        if payload is not None and not payload.get("iss"):
            vulns.append({
                "type": "Missing Issuer Claim",
                "severity": "low",
                "detail": "JWT has no 'iss' (issuer) claim.",
                "remediation": "Include an 'iss' claim to identify the token issuer.",
                "jwt_header": header,
            })

        # Check for sensitive data in payload
        if payload is not None:
            sensitive_found = [k for k in payload if k.lower() in _SENSITIVE_PAYLOAD_KEYS]
            if sensitive_found:
                vulns.append({
                    "type": "Sensitive Data in Payload",
                    "severity": "high",
                    "detail": f"JWT payload contains sensitive keys: {', '.join(sensitive_found)}. "
                              "JWT payloads are base64-encoded, not encrypted.",
                    "remediation": "Never store sensitive data in JWT payload. Payload is not encrypted.",
                    "sensitive_keys": sensitive_found,
                    "jwt_header": header,
                })

        # Check jku/x5u header injection possibility
        if "jku" in header or "x5u" in header:
            vulns.append({
                "type": "JKU/X5U Header Injection Possible",
                "severity": "high",
                "detail": "JWT uses jku or x5u header which can be exploited for SSRF/key confusion.",
                "remediation": "Validate jku/x5u URLs against a strict whitelist.",
                "jwt_header": header,
            })

        return vulns

    @staticmethod
    def _decode_jwt(jwt_str: str) -> Tuple[Optional[Dict], Optional[Dict]]:
        """Decode JWT header and payload without verification."""
        try:
            parts = jwt_str.split(".")
            if len(parts) < 2:
                return None, None

            def _b64decode(s: str) -> Dict:
                # Add padding
                padding = 4 - len(s) % 4
                if padding != 4:
                    s += "=" * padding
                decoded = base64.urlsafe_b64decode(s)
                return json.loads(decoded)

            header = _b64decode(parts[0])
            payload = _b64decode(parts[1])
            return header, payload
        except Exception as exc:
            logger.debug("JWT decode error: %s", exc)
            return None, None
