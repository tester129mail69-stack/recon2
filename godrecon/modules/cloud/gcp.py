"""GCP asset detection for GODRECON."""

from __future__ import annotations

import json
import re
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
    """Return the first label of a domain."""
    base = re.sub(r'^www\.', '', domain)
    base = re.sub(r'\.[a-z]{2,}$', '', base)
    return base.split(".")[0].lower()


class GCPDetector:
    """Detect exposed GCP resources for a target."""

    def __init__(self) -> None:
        """Initialise the detector and load patterns."""
        self._patterns = _load_cloud_patterns()

    async def detect(
        self, target: str, http: AsyncHTTPClient, max_patterns: int = 10
    ) -> List[Dict[str, Any]]:
        """Detect GCP resources related to *target*.

        Args:
            target: Domain name of the target.
            http: Shared async HTTP client.
            max_patterns: Maximum number of bucket name patterns to check.

        Returns:
            List of finding dicts with type, url, status, severity.
        """
        findings: List[Dict[str, Any]] = []
        base_name = _strip_domain(target)
        patterns: List[str] = (
            self._patterns.get("gcp_storage", {}).get("patterns", [])
        )

        for pattern in patterns[:max_patterns]:
            bucket = pattern.replace("{target}", base_name)

            # GCS bucket check
            gcs_url = f"https://storage.googleapis.com/{bucket}"
            try:
                resp = await http.get(gcs_url, allow_redirects=False)
                status = resp.get("status", 0) if resp else 0
                if status == 200:
                    findings.append({
                        "type": "gcp_storage_public",
                        "url": gcs_url,
                        "bucket": bucket,
                        "status": status,
                        "severity": "high",
                        "description": f"GCP Storage bucket '{bucket}' is publicly readable.",
                    })
                elif status == 403:
                    findings.append({
                        "type": "gcp_storage_exists",
                        "url": gcs_url,
                        "bucket": bucket,
                        "status": status,
                        "severity": "info",
                        "description": f"GCP Storage bucket '{bucket}' exists (access denied).",
                    })
            except Exception as exc:  # noqa: BLE001
                logger.debug("GCS check failed for %s: %s", gcs_url, exc)

            # Firebase Realtime Database check
            firebase_url = f"https://{bucket}-default-rtdb.firebaseio.com/.json"
            try:
                resp = await http.get(firebase_url, allow_redirects=False)
                status = resp.get("status", 0) if resp else 0
                if status == 200:
                    findings.append({
                        "type": "firebase_public",
                        "url": firebase_url,
                        "bucket": bucket,
                        "status": status,
                        "severity": "high",
                        "description": f"Firebase Realtime Database '{bucket}' is publicly readable.",
                    })
                elif status == 403:
                    findings.append({
                        "type": "firebase_exists",
                        "url": firebase_url,
                        "bucket": bucket,
                        "status": status,
                        "severity": "info",
                        "description": f"Firebase Realtime Database '{bucket}' exists (access denied).",
                    })
            except Exception as exc:  # noqa: BLE001
                logger.debug("Firebase check failed for %s: %s", firebase_url, exc)

        return findings
