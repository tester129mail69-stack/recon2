"""Security headers analysis for GODRECON.

Provides :class:`SecurityHeadersAnalyzer` which inspects HTTP response headers
for security-relevant settings and produces scored findings.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Header definitions
# ---------------------------------------------------------------------------

# (header_name_lower, severity_if_missing, description)
_CRITICAL_HEADERS: List[Tuple[str, str, str]] = [
    (
        "strict-transport-security",
        "medium",
        "HSTS not configured. Without HSTS the browser may connect over plain HTTP.",
    ),
    (
        "content-security-policy",
        "medium",
        "Content-Security-Policy is missing. CSP helps mitigate XSS attacks.",
    ),
    (
        "x-frame-options",
        "medium",
        "X-Frame-Options is missing. The page may be embeddable in iframes (clickjacking).",
    ),
    (
        "x-content-type-options",
        "low",
        "X-Content-Type-Options is missing. Browsers may MIME-sniff responses.",
    ),
    (
        "referrer-policy",
        "low",
        "Referrer-Policy is missing. Sensitive URL data may leak to third parties.",
    ),
]

_HSTS_MIN_AGE = 15768000  # 6 months in seconds


class SecurityHeadersAnalyzer:
    """Analyse HTTP security headers and return scored findings.

    Args:
        headers: HTTP response headers dict (keys should be lowercase).
        url: The URL that was probed (for context in findings).
    """

    def __init__(self, headers: Dict[str, str], url: str = "") -> None:
        self._headers = {k.lower(): v for k, v in headers.items()}
        self._url = url

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self) -> Dict[str, Any]:
        """Run all header checks and return a structured result.

        Returns:
            Dict with keys ``score``, ``grade``, ``findings``, ``headers_present``,
            ``headers_missing``, and ``details``.
        """
        issues: List[Dict[str, Any]] = []
        score = 100

        # --- HSTS ---
        hsts = self._check_hsts()
        issues.extend(hsts["issues"])
        score -= hsts["deduction"]

        # --- CSP ---
        csp = self._check_csp()
        issues.extend(csp["issues"])
        score -= csp["deduction"]

        # --- X-Frame-Options ---
        xfo = self._check_x_frame_options()
        issues.extend(xfo["issues"])
        score -= xfo["deduction"]

        # --- X-Content-Type-Options ---
        xcto = self._check_x_content_type_options()
        issues.extend(xcto["issues"])
        score -= xcto["deduction"]

        # --- X-XSS-Protection ---
        xxp = self._check_x_xss_protection()
        issues.extend(xxp["issues"])
        score -= xxp["deduction"]

        # --- Referrer-Policy ---
        rp = self._check_referrer_policy()
        issues.extend(rp["issues"])
        score -= rp["deduction"]

        # --- Permissions-Policy ---
        pp = self._check_permissions_policy()
        issues.extend(pp["issues"])
        score -= pp["deduction"]

        # --- Cross-Origin headers ---
        co = self._check_cross_origin_headers()
        issues.extend(co["issues"])
        score -= co["deduction"]

        # --- Cache-Control ---
        cc = self._check_cache_control()
        issues.extend(cc["issues"])
        score -= cc["deduction"]

        # --- Set-Cookie ---
        ck = self._check_cookies()
        issues.extend(ck["issues"])
        score -= ck["deduction"]

        score = max(0, score)
        grade = self._score_to_grade(score)

        headers_present = [h for h in _CRITICAL_HEADERS if h[0] in self._headers]
        headers_missing = [h for h in _CRITICAL_HEADERS if h[0] not in self._headers]

        return {
            "url": self._url,
            "score": score,
            "grade": grade,
            "issues": issues,
            "headers_present": [h[0] for h in headers_present],
            "headers_missing": [h[0] for h in headers_missing],
            "raw_headers": self._headers,
        }

    # ------------------------------------------------------------------
    # Individual header checks
    # ------------------------------------------------------------------

    def _check_hsts(self) -> Dict[str, Any]:
        """Check Strict-Transport-Security header."""
        issues: List[Dict[str, Any]] = []
        deduction = 0
        value = self._headers.get("strict-transport-security", "")

        if not value:
            issues.append({
                "header": "Strict-Transport-Security",
                "issue": "HSTS header is missing",
                "severity": "medium",
                "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            })
            deduction += 15
        else:
            # Check max-age
            m = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
            if m:
                max_age = int(m.group(1))
                if max_age < _HSTS_MIN_AGE:
                    issues.append({
                        "header": "Strict-Transport-Security",
                        "issue": f"HSTS max-age is too short ({max_age}s < {_HSTS_MIN_AGE}s)",
                        "severity": "low",
                        "recommendation": f"Increase max-age to at least {_HSTS_MIN_AGE}",
                    })
                    deduction += 5
            else:
                issues.append({
                    "header": "Strict-Transport-Security",
                    "issue": "HSTS max-age is missing from the header value",
                    "severity": "medium",
                    "recommendation": "Include max-age in HSTS header",
                })
                deduction += 10
            if "includesubdomains" not in value.lower():
                issues.append({
                    "header": "Strict-Transport-Security",
                    "issue": "HSTS does not include subdomains",
                    "severity": "low",
                    "recommendation": "Add includeSubDomains directive",
                })
                deduction += 2
        return {"issues": issues, "deduction": deduction}

    def _check_csp(self) -> Dict[str, Any]:
        """Check Content-Security-Policy header."""
        issues: List[Dict[str, Any]] = []
        deduction = 0
        value = self._headers.get("content-security-policy", "")

        if not value:
            issues.append({
                "header": "Content-Security-Policy",
                "issue": "CSP header is missing",
                "severity": "medium",
                "recommendation": "Add a Content-Security-Policy header to mitigate XSS",
            })
            deduction += 15
        else:
            if "'unsafe-inline'" in value:
                issues.append({
                    "header": "Content-Security-Policy",
                    "issue": "CSP contains 'unsafe-inline' which weakens XSS protection",
                    "severity": "medium",
                    "recommendation": "Remove 'unsafe-inline' or use nonces/hashes",
                })
                deduction += 8
            if "'unsafe-eval'" in value:
                issues.append({
                    "header": "Content-Security-Policy",
                    "issue": "CSP contains 'unsafe-eval' which enables code injection",
                    "severity": "medium",
                    "recommendation": "Remove 'unsafe-eval' from CSP policy",
                })
                deduction += 8
            if "default-src" not in value and "script-src" not in value:
                issues.append({
                    "header": "Content-Security-Policy",
                    "issue": "CSP lacks default-src or script-src directive",
                    "severity": "low",
                    "recommendation": "Add a default-src or script-src directive",
                })
                deduction += 5
        return {"issues": issues, "deduction": deduction}

    def _check_x_frame_options(self) -> Dict[str, Any]:
        """Check X-Frame-Options header."""
        issues: List[Dict[str, Any]] = []
        deduction = 0
        value = self._headers.get("x-frame-options", "").upper()

        if not value:
            issues.append({
                "header": "X-Frame-Options",
                "issue": "X-Frame-Options is missing (clickjacking risk)",
                "severity": "medium",
                "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
            })
            deduction += 10
        elif value not in ("DENY", "SAMEORIGIN") and not value.startswith("ALLOW-FROM"):
            issues.append({
                "header": "X-Frame-Options",
                "issue": f"X-Frame-Options has unexpected value: {value!r}",
                "severity": "low",
                "recommendation": "Use DENY or SAMEORIGIN",
            })
            deduction += 3
        return {"issues": issues, "deduction": deduction}

    def _check_x_content_type_options(self) -> Dict[str, Any]:
        """Check X-Content-Type-Options header."""
        issues: List[Dict[str, Any]] = []
        deduction = 0
        value = self._headers.get("x-content-type-options", "").lower()

        if not value:
            issues.append({
                "header": "X-Content-Type-Options",
                "issue": "X-Content-Type-Options is missing (MIME sniffing risk)",
                "severity": "low",
                "recommendation": "Add: X-Content-Type-Options: nosniff",
            })
            deduction += 5
        elif value != "nosniff":
            issues.append({
                "header": "X-Content-Type-Options",
                "issue": f"Unexpected value for X-Content-Type-Options: {value!r}",
                "severity": "low",
                "recommendation": "Use 'nosniff'",
            })
            deduction += 3
        return {"issues": issues, "deduction": deduction}

    def _check_x_xss_protection(self) -> Dict[str, Any]:
        """Check X-XSS-Protection header."""
        issues: List[Dict[str, Any]] = []
        deduction = 0
        value = self._headers.get("x-xss-protection", "")

        if value == "0":
            issues.append({
                "header": "X-XSS-Protection",
                "issue": "X-XSS-Protection is explicitly disabled",
                "severity": "low",
                "recommendation": "Use '1; mode=block' or rely solely on CSP",
            })
            deduction += 3
        return {"issues": issues, "deduction": deduction}

    def _check_referrer_policy(self) -> Dict[str, Any]:
        """Check Referrer-Policy header."""
        issues: List[Dict[str, Any]] = []
        deduction = 0
        value = self._headers.get("referrer-policy", "").lower()

        _unsafe = {"unsafe-url", "no-referrer-when-downgrade", ""}
        if not value:
            issues.append({
                "header": "Referrer-Policy",
                "issue": "Referrer-Policy is missing",
                "severity": "low",
                "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
            })
            deduction += 3
        elif value in _unsafe:
            issues.append({
                "header": "Referrer-Policy",
                "issue": f"Referrer-Policy '{value}' leaks referrer information",
                "severity": "low",
                "recommendation": "Use 'strict-origin-when-cross-origin' or 'no-referrer'",
            })
            deduction += 3
        return {"issues": issues, "deduction": deduction}

    def _check_permissions_policy(self) -> Dict[str, Any]:
        """Check Permissions-Policy header."""
        issues: List[Dict[str, Any]] = []
        deduction = 0
        value = self._headers.get("permissions-policy", "")

        if not value:
            issues.append({
                "header": "Permissions-Policy",
                "issue": "Permissions-Policy (Feature-Policy) is missing",
                "severity": "low",
                "recommendation": "Add Permissions-Policy to restrict browser features",
            })
            deduction += 2
        return {"issues": issues, "deduction": deduction}

    def _check_cross_origin_headers(self) -> Dict[str, Any]:
        """Check COOP, CORP, COEP headers."""
        issues: List[Dict[str, Any]] = []
        deduction = 0
        for header in ("cross-origin-opener-policy", "cross-origin-resource-policy", "cross-origin-embedder-policy"):
            if header not in self._headers:
                issues.append({
                    "header": header.upper(),
                    "issue": f"{header.upper()} is missing",
                    "severity": "low",
                    "recommendation": f"Consider setting {header}",
                })
                deduction += 1
        return {"issues": issues, "deduction": deduction}

    def _check_cache_control(self) -> Dict[str, Any]:
        """Check Cache-Control header for sensitive page caching."""
        issues: List[Dict[str, Any]] = []
        deduction = 0
        value = self._headers.get("cache-control", "").lower()

        if not value:
            issues.append({
                "header": "Cache-Control",
                "issue": "Cache-Control header is missing",
                "severity": "low",
                "recommendation": "Add Cache-Control: no-store, no-cache for sensitive pages",
            })
            deduction += 2
        elif "public" in value and "no-store" not in value:
            issues.append({
                "header": "Cache-Control",
                "issue": "Cache-Control is set to public — sensitive data may be cached",
                "severity": "low",
                "recommendation": "Use no-store or private for authenticated/sensitive content",
            })
            deduction += 2
        return {"issues": issues, "deduction": deduction}

    def _check_cookies(self) -> Dict[str, Any]:
        """Check Set-Cookie flags."""
        issues: List[Dict[str, Any]] = []
        deduction = 0
        cookie_header = self._headers.get("set-cookie", "")

        if cookie_header:
            lower = cookie_header.lower()
            if "httponly" not in lower:
                issues.append({
                    "header": "Set-Cookie",
                    "issue": "Cookie is missing HttpOnly flag",
                    "severity": "medium",
                    "recommendation": "Add HttpOnly flag to prevent JavaScript access",
                })
                deduction += 5
            if "secure" not in lower:
                issues.append({
                    "header": "Set-Cookie",
                    "issue": "Cookie is missing Secure flag",
                    "severity": "medium",
                    "recommendation": "Add Secure flag to prevent transmission over HTTP",
                })
                deduction += 5
            if "samesite" not in lower:
                issues.append({
                    "header": "Set-Cookie",
                    "issue": "Cookie is missing SameSite attribute",
                    "severity": "low",
                    "recommendation": "Add SameSite=Strict or SameSite=Lax to prevent CSRF",
                })
                deduction += 3
        return {"issues": issues, "deduction": deduction}

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    @staticmethod
    def _score_to_grade(score: int) -> str:
        """Convert a numeric score to a letter grade.

        Args:
            score: Numeric security score (0–100).

        Returns:
            Letter grade string (A+ … F).
        """
        if score >= 95:
            return "A+"
        if score >= 85:
            return "A"
        if score >= 75:
            return "B"
        if score >= 60:
            return "C"
        if score >= 45:
            return "D"
        return "F"
