"""CORS misconfiguration analysis for GODRECON.

Provides :class:`CORSAnalyzer` which sends requests with attacker-controlled
Origin headers and inspects Access-Control-Allow-Origin responses.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_ATTACKER_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
]


class CORSAnalyzer:
    """Test a URL for CORS misconfigurations.

    Sends several requests with crafted ``Origin`` headers and checks whether
    the server reflects arbitrary origins or allows wildcard with credentials.

    Args:
        http_client: Pre-configured :class:`AsyncHTTPClient`.
        concurrency: Maximum simultaneous requests.
    """

    def __init__(
        self,
        http_client: AsyncHTTPClient,
        concurrency: int = 20,
    ) -> None:
        self._client = http_client
        self._concurrency = concurrency

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def analyze(self, url: str, target_domain: str) -> Dict[str, Any]:
        """Run CORS checks against *url*.

        Tests:
        * Wildcard ``Access-Control-Allow-Origin: *``
        * Origin reflection (arbitrary origin echoed back)
        * Null origin acceptance
        * Subdomain of target origin
        * Wildcard + ``Access-Control-Allow-Credentials: true`` (critical)

        Args:
            url: Full URL to probe.
            target_domain: The base target domain (used to build subdomain origin).

        Returns:
            Dict with ``url``, ``vulnerable``, ``severity``, and ``findings``.
        """
        findings: List[Dict[str, Any]] = []
        origins_to_test = list(_ATTACKER_ORIGINS) + [
            f"https://evil.{target_domain}",
            f"https://sub.{target_domain}",
        ]

        sem = asyncio.Semaphore(self._concurrency)

        async def _test(origin: str) -> Optional[Dict[str, Any]]:
            async with sem:
                return await self._test_origin(url, origin)

        tasks = [asyncio.create_task(_test(o)) for o in origins_to_test]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, dict) and r:
                findings.append(r)

        # Also check wildcard without specific origin
        wildcard_result = await self._check_wildcard(url)
        if wildcard_result:
            findings.append(wildcard_result)

        severity = "info"
        vulnerable = False
        for f in findings:
            f_sev = f.get("severity", "info")
            if f_sev == "critical":
                severity = "critical"
                vulnerable = True
            elif f_sev == "high" and severity not in ("critical",):
                severity = "high"
                vulnerable = True
            elif f_sev == "medium" and severity not in ("critical", "high"):
                severity = "medium"
                vulnerable = True

        return {
            "url": url,
            "vulnerable": vulnerable,
            "severity": severity,
            "findings": findings,
        }

    # ------------------------------------------------------------------
    # Internal probes
    # ------------------------------------------------------------------

    async def _test_origin(self, url: str, origin: str) -> Optional[Dict[str, Any]]:
        """Send a request with a crafted Origin header and inspect the response.

        Args:
            url: Target URL.
            origin: Origin header value to send.

        Returns:
            Issue dict if a misconfiguration is found, else ``None``.
        """
        try:
            resp = await self._client.get(
                url,
                headers={"Origin": origin},
                allow_redirects=True,
            )
            resp_headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
            acao = resp_headers.get("access-control-allow-origin", "")
            acac = resp_headers.get("access-control-allow-credentials", "").lower()
            credentials = acac == "true"

            if not acao:
                return None

            if acao == "*" and credentials:
                return {
                    "type": "wildcard_with_credentials",
                    "origin_sent": origin,
                    "acao": acao,
                    "credentials": credentials,
                    "severity": "critical",
                    "description": (
                        "CORS wildcard (*) with Access-Control-Allow-Credentials: true. "
                        "This is invalid per spec but may be exploited in some browsers."
                    ),
                }
            if acao == origin and origin != "*":
                sev = "critical" if credentials else "high"
                return {
                    "type": "origin_reflection",
                    "origin_sent": origin,
                    "acao": acao,
                    "credentials": credentials,
                    "severity": sev,
                    "description": (
                        f"Server reflects arbitrary origin '{origin}' in ACAO header"
                        + (" with credentials" if credentials else "")
                        + ". Cross-origin requests from any domain are allowed."
                    ),
                }
            if acao == "null" and origin == "null":
                sev = "high" if credentials else "medium"
                return {
                    "type": "null_origin_accepted",
                    "origin_sent": origin,
                    "acao": acao,
                    "credentials": credentials,
                    "severity": sev,
                    "description": (
                        "Server accepts 'null' origin. Sandboxed iframes can exploit this."
                    ),
                }
        except Exception as exc:  # noqa: BLE001
            logger.debug("CORS test failed for %s (origin=%s): %s", url, origin, exc)
        return None

    async def _check_wildcard(self, url: str) -> Optional[Dict[str, Any]]:
        """Check for a wildcard ACAO without a specific Origin header.

        Args:
            url: Target URL.

        Returns:
            Issue dict if wildcard CORS is present, else ``None``.
        """
        try:
            resp = await self._client.get(url, allow_redirects=True)
            resp_headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
            acao = resp_headers.get("access-control-allow-origin", "")
            if acao == "*":
                return {
                    "type": "wildcard_cors",
                    "origin_sent": None,
                    "acao": acao,
                    "credentials": False,
                    "severity": "medium",
                    "description": (
                        "CORS wildcard (*) is set — any origin can make cross-origin "
                        "requests to this resource."
                    ),
                }
        except Exception as exc:  # noqa: BLE001
            logger.debug("CORS wildcard check failed for %s: %s", url, exc)
        return None
