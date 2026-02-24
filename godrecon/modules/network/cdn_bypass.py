"""CDN/WAF bypass and origin IP discovery sub-module for GODRECON.

Detects whether a target is behind a CDN or WAF, then applies multiple
techniques to discover the real origin IP:

* Common origin-revealing subdomains
* MX record IP extraction
* SPF record IP extraction
* HTTP header analysis (X-Forwarded-For, Server)
* Favicon hash comparison
* HTML body hash comparison
"""

from __future__ import annotations

import asyncio
import fnmatch
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from godrecon.utils.dns_resolver import AsyncDNSResolver
from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_DATA_DIR = Path(__file__).parent.parent.parent / "data"
_CDN_SIGNATURES_FILE = _DATA_DIR / "cdn_signatures.json"
_ORIGIN_SUBDOMAINS_FILE = _DATA_DIR / "origin_subdomains.json"

# Regex to extract IPv4 from SPF include directives
_IP4_RE = re.compile(r"ip4:([\d.]+(?:/\d+)?)")


def _load_json(path: Path) -> Any:
    """Load JSON from *path*, returning an empty container on error.

    Args:
        path: Filesystem path to a JSON file.

    Returns:
        Parsed JSON (dict or list), or empty dict/list on failure.
    """
    try:
        with path.open() as fh:
            return json.load(fh)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not load %s: %s", path, exc)
        return {}


class CDNBypassDetector:
    """Detect CDN/WAF providers and discover origin IP addresses.

    Example::

        async with AsyncHTTPClient() as http, AsyncDNSResolver() as resolver:
            detector = CDNBypassDetector(http, resolver)
            result = await detector.run("example.com")
    """

    def __init__(
        self,
        http_client: AsyncHTTPClient,
        dns_resolver: AsyncDNSResolver,
    ) -> None:
        """Initialise the detector.

        Args:
            http_client: Configured HTTP client instance.
            dns_resolver: Configured async DNS resolver.
        """
        self._http = http_client
        self._resolver = dns_resolver
        self._cdn_sigs: Dict[str, Any] = _load_json(_CDN_SIGNATURES_FILE)
        self._origin_subs: List[str] = _load_json(_ORIGIN_SUBDOMAINS_FILE) or []

    async def run(self, domain: str) -> Dict[str, Any]:
        """Run CDN detection and origin IP discovery for *domain*.

        Args:
            domain: Target domain name.

        Returns:
            Dict with ``cdn_detected``, ``cdn_provider``, ``origin_ips``,
            ``techniques``, and ``headers`` fields.
        """
        # Step 1: fetch target and collect headers / body / favicon
        target_data = await self._fetch_target(domain)

        # Step 2: detect CDN from headers and DNS
        cdn_provider, cdn_evidence = await self._detect_cdn(domain, target_data)

        # Step 3: discover origin IPs
        origin_ips, technique_results = await self._discover_origin_ips(
            domain, target_data, cdn_provider
        )

        # Step 4: validate origin IPs by content comparison
        validated = await self._validate_origin_ips(domain, target_data, origin_ips)

        return {
            "cdn_detected": cdn_provider is not None,
            "cdn_provider": cdn_provider,
            "cdn_evidence": cdn_evidence,
            "origin_ips": list(origin_ips),
            "validated_origin_ips": validated,
            "techniques": technique_results,
            "response_headers": target_data.get("headers", {}),
        }

    # ------------------------------------------------------------------
    # CDN detection
    # ------------------------------------------------------------------

    async def _detect_cdn(
        self, domain: str, target_data: Dict[str, Any]
    ) -> tuple[Optional[str], List[str]]:
        """Detect CDN/WAF from response headers and CNAME records.

        Args:
            domain: Target domain.
            target_data: Dict of fetched response data for the domain.

        Returns:
            Tuple of (provider_name or None, list of evidence strings).
        """
        evidence: List[str] = []
        headers = {k.lower(): v for k, v in target_data.get("headers", {}).items()}

        # Check response headers and server string
        for provider, sig in self._cdn_sigs.items():
            matched = False
            for hdr in sig.get("headers", []):
                if hdr.lower() in headers:
                    evidence.append(f"header:{hdr}")
                    matched = True
            for srv in sig.get("server_header", []):
                if srv.lower() in headers.get("server", "").lower():
                    evidence.append(f"server:{srv}")
                    matched = True
            if matched:
                return provider, evidence

        # Check CNAME records
        try:
            cnames = await self._resolver.resolve(domain, "CNAME")
            for provider, sig in self._cdn_sigs.items():
                for pattern in sig.get("cnames", []):
                    pat_lower = pattern.lower()
                    for cname in cnames:
                        cname_str = str(cname).rstrip(".").lower()
                        if fnmatch.fnmatch(cname_str, pat_lower):
                            evidence.append(f"cname:{cname}")
                            return provider, evidence
        except Exception as exc:  # noqa: BLE001
            logger.debug("CNAME lookup failed for %s: %s", domain, exc)

        # Check nameservers
        try:
            ns_records = await self._resolver.resolve(domain, "NS")
            for provider, sig in self._cdn_sigs.items():
                for pattern in sig.get("nameservers", []):
                    pat_lower = pattern.lower()
                    for ns in ns_records:
                        ns_str = str(ns).rstrip(".").lower()
                        if fnmatch.fnmatch(ns_str, pat_lower):
                            evidence.append(f"ns:{ns}")
                            return provider, evidence
        except Exception as exc:  # noqa: BLE001
            logger.debug("NS lookup failed for %s: %s", domain, exc)

        return None, []

    # ------------------------------------------------------------------
    # Origin IP discovery
    # ------------------------------------------------------------------

    async def _discover_origin_ips(
        self,
        domain: str,
        target_data: Dict[str, Any],
        cdn_provider: Optional[str],
    ) -> tuple[Set[str], Dict[str, Any]]:
        """Run all origin IP discovery techniques.

        Args:
            domain: Target domain.
            target_data: Pre-fetched response data for the domain.
            cdn_provider: Detected CDN provider name (or ``None``).

        Returns:
            Tuple of (set of candidate IPs, per-technique result dict).
        """
        all_ips: Set[str] = set()
        techniques: Dict[str, Any] = {}

        results = await asyncio.gather(
            self._check_origin_subdomains(domain),
            self._check_mx_records(domain),
            self._check_spf_ips(domain),
            self._check_headers(target_data),
            return_exceptions=True,
        )

        sub_ips, sub_detail = self._safe_result(results[0], [], {})
        mx_ips, mx_detail = self._safe_result(results[1], [], {})
        spf_ips, spf_detail = self._safe_result(results[2], [], {})
        hdr_ips, hdr_detail = self._safe_result(results[3], [], {})

        all_ips.update(sub_ips)
        all_ips.update(mx_ips)
        all_ips.update(spf_ips)
        all_ips.update(hdr_ips)

        techniques["origin_subdomains"] = {"ips": sub_ips, "detail": sub_detail}
        techniques["mx_records"] = {"ips": mx_ips, "detail": mx_detail}
        techniques["spf_ips"] = {"ips": spf_ips, "detail": spf_detail}
        techniques["header_leakage"] = {"ips": hdr_ips, "detail": hdr_detail}

        return all_ips, techniques

    async def _check_origin_subdomains(self, domain: str) -> tuple[List[str], Dict[str, Any]]:
        """Resolve common origin-revealing subdomains.

        Args:
            domain: Base domain.

        Returns:
            Tuple of (list of IPs found, dict mapping subdomain → IPs).
        """
        ips: List[str] = []
        detail: Dict[str, Any] = {}
        tasks = {
            f"{sub}.{domain}": asyncio.create_task(
                self._resolve_a(f"{sub}.{domain}")
            )
            for sub in self._origin_subs
        }
        for fqdn, task in tasks.items():
            try:
                addrs = await task
                if addrs:
                    ips.extend(addrs)
                    detail[fqdn] = addrs
            except Exception:  # noqa: BLE001
                pass
        return ips, detail

    async def _check_mx_records(self, domain: str) -> tuple[List[str], Dict[str, Any]]:
        """Extract IPs from MX record hosts.

        Args:
            domain: Target domain.

        Returns:
            Tuple of (list of IPs, detail dict).
        """
        ips: List[str] = []
        detail: Dict[str, Any] = {}
        try:
            mx_records = await self._resolver.resolve(domain, "MX")
            for mx in mx_records:
                # Strip priority if present
                host = str(mx).split()[-1].rstrip(".")
                addrs = await self._resolve_a(host)
                if addrs:
                    ips.extend(addrs)
                    detail[host] = addrs
        except Exception as exc:  # noqa: BLE001
            logger.debug("MX lookup failed for %s: %s", domain, exc)
        return ips, detail

    async def _check_spf_ips(self, domain: str) -> tuple[List[str], Dict[str, Any]]:
        """Extract IP addresses from SPF TXT record.

        Args:
            domain: Target domain.

        Returns:
            Tuple of (list of IP strings, detail dict).
        """
        ips: List[str] = []
        detail: Dict[str, Any] = {}
        try:
            txt_records = await self._resolver.resolve(domain, "TXT")
            for record in txt_records:
                r = str(record).strip('"')
                if "v=spf1" in r:
                    found = _IP4_RE.findall(r)
                    # Only collect plain IPs (no CIDR) for validation
                    for item in found:
                        plain = item.split("/")[0]
                        ips.append(plain)
                    detail["spf_record"] = r
                    detail["extracted_ips"] = found
        except Exception as exc:  # noqa: BLE001
            logger.debug("SPF TXT lookup failed for %s: %s", domain, exc)
        return ips, detail

    @staticmethod
    def _check_headers(target_data: Dict[str, Any]) -> tuple[List[str], Dict[str, Any]]:
        """Check HTTP response headers for IP leakage.

        Args:
            target_data: Pre-fetched response data dict.

        Returns:
            Tuple of (list of leaked IPs, detail dict).
        """
        headers = {k.lower(): v for k, v in target_data.get("headers", {}).items()}
        ips: List[str] = []
        detail: Dict[str, Any] = {}
        ip_pattern = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

        for hdr in ("x-forwarded-for", "x-real-ip", "x-origin-ip", "x-originating-ip", "via"):
            val = headers.get(hdr, "")
            if val:
                found = ip_pattern.findall(val)
                for ip in found:
                    if not _is_private_ip(ip):
                        ips.append(ip)
                        detail[hdr] = val
        return ips, detail

    # ------------------------------------------------------------------
    # Origin IP validation
    # ------------------------------------------------------------------

    async def _validate_origin_ips(
        self,
        domain: str,
        target_data: Dict[str, Any],
        candidate_ips: Set[str],
    ) -> List[Dict[str, Any]]:
        """Compare candidate IPs' HTTP response to the CDN target.

        Args:
            domain: Target domain.
            target_data: Pre-fetched response data for the domain.
            candidate_ips: Set of candidate origin IPs.

        Returns:
            List of validated origin IP dicts with ``ip`` and ``confidence`` fields.
        """
        if not candidate_ips:
            return []

        target_favicon_hash = target_data.get("favicon_hash")
        target_body_hash = target_data.get("body_hash")

        tasks = {
            ip: asyncio.create_task(self._fetch_ip_response(ip))
            for ip in candidate_ips
        }
        validated: List[Dict[str, Any]] = []
        for ip, task in tasks.items():
            try:
                ip_data = await task
                confidence = self._compare_responses(
                    target_favicon_hash, target_body_hash, ip_data
                )
                if confidence > 0:
                    validated.append({"ip": ip, "confidence": confidence, "data": ip_data})
            except Exception as exc:  # noqa: BLE001
                logger.debug("Validation fetch failed for %s: %s", ip, exc)

        return sorted(validated, key=lambda x: x["confidence"], reverse=True)

    async def _fetch_target(self, domain: str) -> Dict[str, Any]:
        """Fetch HTTP response data for the CDN-fronted target.

        Args:
            domain: Target domain.

        Returns:
            Dict with ``headers``, ``body_hash``, ``favicon_hash``, ``status``.
        """
        try:
            resp = await self._http.get(
                f"https://{domain}", headers={"Host": domain}
            )
            body = resp.get("body", "") or ""
            favicon_hash = await self._get_favicon_hash(domain)
            return {
                "status": resp.get("status"),
                "headers": resp.get("headers") or {},
                "body_hash": hashlib.sha256(body.encode(errors="replace")).hexdigest(),
                "favicon_hash": favicon_hash,
            }
        except Exception as exc:  # noqa: BLE001
            logger.debug("Target fetch failed for %s: %s", domain, exc)
            return {"status": None, "headers": {}, "body_hash": None, "favicon_hash": None}

    async def _fetch_ip_response(self, ip: str) -> Dict[str, Any]:
        """Fetch HTTP response data directly from an IP address.

        Args:
            ip: IPv4 address to probe.

        Returns:
            Dict with ``body_hash`` and ``favicon_hash``.
        """
        try:
            resp = await self._http.get(f"http://{ip}")
            body = resp.get("body", "") or ""
            favicon_hash = await self._get_favicon_hash(ip)
            return {
                "status": resp.get("status"),
                "body_hash": hashlib.sha256(body.encode(errors="replace")).hexdigest(),
                "favicon_hash": favicon_hash,
            }
        except Exception as exc:  # noqa: BLE001
            logger.debug("IP fetch failed for %s: %s", ip, exc)
            return {"status": None, "body_hash": None, "favicon_hash": None}

    async def _get_favicon_hash(self, host: str) -> Optional[str]:
        """Fetch /favicon.ico and return its MD5 hash.

        Args:
            host: Domain or IP to fetch favicon from.

        Returns:
            Hex MD5 digest or ``None`` on failure.
        """
        for scheme in ("https", "http"):
            try:
                resp = await self._http.get(f"{scheme}://{host}/favicon.ico")
                body = resp.get("body", "")
                if body and resp.get("status") == 200:
                    return hashlib.sha256(
                        body.encode(errors="replace")
                    ).hexdigest()
            except Exception:  # noqa: BLE001
                pass
        return None

    @staticmethod
    def _compare_responses(
        target_favicon: Optional[str],
        target_body: Optional[str],
        ip_data: Dict[str, Any],
    ) -> float:
        """Score similarity between target and candidate origin responses.

        Args:
            target_favicon: MD5 of the CDN target's favicon.
            target_body: MD5 of the CDN target's response body.
            ip_data: Response data dict for the candidate IP.

        Returns:
            Confidence score between 0.0 (no match) and 1.0 (full match).
        """
        score = 0.0
        if target_favicon and ip_data.get("favicon_hash") == target_favicon:
            score += 0.6
        if target_body and ip_data.get("body_hash") == target_body:
            score += 0.4
        return round(score, 2)

    async def _resolve_a(self, hostname: str) -> List[str]:
        """Resolve A records for *hostname*.

        Args:
            hostname: FQDN to resolve.

        Returns:
            List of IPv4 address strings.
        """
        try:
            records = await self._resolver.resolve(hostname, "A")
            return [str(r) for r in records if r]
        except Exception:  # noqa: BLE001
            return []

    @staticmethod
    def _safe_result(
        value: Any,
        default_ips: List[str],
        default_detail: Dict[str, Any],
    ) -> tuple[List[str], Dict[str, Any]]:
        """Unwrap a gather result, returning defaults on exception.

        Args:
            value: Result from ``asyncio.gather`` (may be an exception).
            default_ips: Default IP list on failure.
            default_detail: Default detail dict on failure.

        Returns:
            Tuple of (ips, detail).
        """
        if isinstance(value, Exception):
            return default_ips, default_detail
        return value


# Private / reserved IP ranges (RFC1918, loopback, link-local)
_PRIVATE_RANGES = [
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^127\."),
    re.compile(r"^169\.254\."),
]


def _is_private_ip(ip: str) -> bool:
    """Return ``True`` if *ip* is in a private/reserved range.

    Args:
        ip: IPv4 address string.

    Returns:
        ``True`` if private, ``False`` if public.
    """
    return any(pat.match(ip) for pat in _PRIVATE_RANGES)
