"""AWS asset detection for GODRECON."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_DATA_DIR = Path(__file__).parent.parent.parent / "data"


def _load_cloud_patterns() -> Dict[str, Any]:
    """Load cloud bucket patterns from the bundled JSON file."""
    path = _DATA_DIR / "cloud_patterns.json"
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to load cloud patterns: %s", exc)
    return {}


def _strip_domain(domain: str) -> str:
    """Return the first label of a domain (strips TLD and subdomains).

    Args:
        domain: Full domain string.

    Returns:
        First DNS label, lower-cased.
    """
    import re
    base = re.sub(r'^www\.', '', domain)
    base = re.sub(r'\.[a-z]{2,}$', '', base)
    return base.split(".")[0].lower()


class AWSDetector:
    """Detect exposed AWS resources for a target."""

    def __init__(self) -> None:
        """Initialise the detector and load patterns."""
        self._patterns = _load_cloud_patterns()

    async def detect(
        self, target: str, http: AsyncHTTPClient, max_patterns: int = 10
    ) -> List[Dict[str, Any]]:
        """Detect AWS resources related to *target*.

        Args:
            target: Domain name of the target.
            http: Shared async HTTP client.
            max_patterns: Maximum number of bucket name patterns to check.

        Returns:
            List of finding dicts with type, url, status, public, severity.
        """
        findings: List[Dict[str, Any]] = []
        base_name = _strip_domain(target)
        patterns: List[str] = self._patterns.get("aws_s3", {}).get("patterns", [])

        checked = 0
        for pattern in patterns[:max_patterns]:
            bucket = pattern.replace("{target}", base_name)
            url = f"https://{bucket}.s3.amazonaws.com"
            try:
                resp = await http.get(url, allow_redirects=False)
                status = resp.get("status", 0) if resp else 0
                headers = {k.lower(): v for k, v in resp.get("headers", {}).items()} if resp else {}

                if status == 200:
                    findings.append({
                        "type": "aws_s3_public",
                        "url": url,
                        "bucket": bucket,
                        "status": status,
                        "public": True,
                        "severity": "high",
                        "description": f"S3 bucket '{bucket}' is publicly readable.",
                    })
                elif status == 403:
                    findings.append({
                        "type": "aws_s3_exists",
                        "url": url,
                        "bucket": bucket,
                        "status": status,
                        "public": False,
                        "severity": "info",
                        "description": f"S3 bucket '{bucket}' exists but access is denied.",
                    })

                # CloudFront detection from any response
                x_cache = headers.get("x-cache", "")
                if "cloudfront" in x_cache.lower():
                    findings.append({
                        "type": "aws_cloudfront",
                        "url": url,
                        "status": status,
                        "severity": "info",
                        "description": f"CloudFront CDN distribution detected (X-Cache: {x_cache}).",
                    })

            except Exception as exc:  # noqa: BLE001
                logger.debug("AWS check failed for %s: %s", url, exc)

            checked += 1

        # Check for CloudFront on the main target
        try:
            resp = await http.get(f"https://{target}", allow_redirects=True)
            if resp:
                headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
                if any("x-amz-" in k for k in headers):
                    findings.append({
                        "type": "aws_hosted",
                        "url": f"https://{target}",
                        "status": resp.get("status"),
                        "severity": "info",
                        "description": f"Target {target} appears to be hosted on AWS (x-amz-* headers detected).",
                    })
        except Exception as exc:  # noqa: BLE001
            logger.debug("AWS main target check failed for %s: %s", target, exc)

        return findings
