"""API security analysis for GODRECON."""

from __future__ import annotations

import re
from typing import Any, Dict, List

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)


class APISecurityChecker:
    """Check API endpoints for security issues."""

    def __init__(self) -> None:
        """Initialise the security checker."""

    async def check(
        self, api_url: str, http: AsyncHTTPClient
    ) -> List[Dict[str, Any]]:
        """Check security posture of *api_url*.

        Checks performed:
        - CORS misconfiguration (wildcard Allow-Origin)
        - Authentication requirement (unauthenticated access)
        - Rate limiting headers presence
        - Verbose error messages on invalid input
        - API version detection

        Args:
            api_url: URL of the API endpoint to check.
            http: Shared async HTTP client.

        Returns:
            List of security finding dicts.
        """
        findings: List[Dict[str, Any]] = []

        try:
            resp = await http.get(api_url, allow_redirects=True)
        except Exception as exc:  # noqa: BLE001
            logger.debug("API security GET failed for %s: %s", api_url, exc)
            return findings

        if not resp:
            return findings

        status = resp.get("status", 0)
        headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
        body = resp.get("body", "")

        # CORS wildcard
        acao = headers.get("access-control-allow-origin", "")
        if acao.strip() == "*":
            findings.append({
                "type": "cors_wildcard",
                "url": api_url,
                "severity": "medium",
                "description": (
                    f"API endpoint {api_url} returns "
                    "'Access-Control-Allow-Origin: *' allowing cross-origin requests."
                ),
            })

        # Unauthenticated access to API paths that typically require auth
        _AUTH_REQUIRED_PATTERNS = ("/api/v", "/api/", "/v1", "/v2", "/v3", "/rest", "/graphql")
        path_lower = api_url.split("?")[0].lower()
        if status == 200 and any(p in path_lower for p in _AUTH_REQUIRED_PATTERNS):
            body_lower = body.lower()
            # Only flag if the response contains data-like content (not just docs/health)
            data_indicators = ['"data"', '"results"', '"items"', '"users"', '"records"', '"access"']
            if any(ind in body_lower for ind in data_indicators):
                findings.append({
                    "type": "unauthenticated_access",
                    "url": api_url,
                    "severity": "high",
                    "description": (
                        f"API endpoint {api_url} returns data without authentication (HTTP 200). "
                        "Verify whether authentication is required."
                    ),
                })
        elif status == 401:
            findings.append({
                "type": "authentication_required",
                "url": api_url,
                "severity": "info",
                "description": f"API endpoint {api_url} requires authentication (HTTP 401).",
            })

        # Rate limiting headers check
        rate_limit_headers = [
            "x-ratelimit-limit", "x-ratelimit-remaining",
            "x-rate-limit-limit", "ratelimit-limit",
        ]
        has_rate_limit = any(h in headers for h in rate_limit_headers)
        if not has_rate_limit and status == 200:
            findings.append({
                "type": "no_rate_limiting",
                "url": api_url,
                "severity": "low",
                "description": (
                    f"API endpoint {api_url} does not appear to implement "
                    "rate limiting (no X-RateLimit-* headers found)."
                ),
            })

        # Verbose error messages via invalid request
        try:
            err_resp = await http.post(
                api_url,
                data="INVALID_PAYLOAD_TEST",
                headers={"Content-Type": "application/json"},
            )
            if err_resp:
                err_body = err_resp.get("body", "").lower()
                verbose_indicators = [
                    "stack trace", "traceback", "exception", "at line",
                    "syntax error", "undefined method", "null pointer",
                ]
                if any(ind in err_body for ind in verbose_indicators):
                    findings.append({
                        "type": "verbose_errors",
                        "url": api_url,
                        "severity": "medium",
                        "description": (
                            f"API endpoint {api_url} returns verbose error messages "
                            "that may reveal internal implementation details."
                        ),
                    })
        except Exception:  # noqa: BLE001
            pass

        # API version detection
        version_match = re.search(r'/v(\d+)', api_url)
        if version_match:
            version = version_match.group(1)
            findings.append({
                "type": "api_version_detected",
                "url": api_url,
                "severity": "info",
                "description": f"API version {version} detected in URL path.",
                "version": version,
            })

        return findings
