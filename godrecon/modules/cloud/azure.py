"""Azure asset detection for GODRECON."""

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


class AzureDetector:
    """Detect exposed Azure resources for a target."""

    def __init__(self) -> None:
        """Initialise the detector and load patterns."""
        self._patterns = _load_cloud_patterns()

    async def detect(
        self, target: str, http: AsyncHTTPClient, max_patterns: int = 10
    ) -> List[Dict[str, Any]]:
        """Detect Azure resources related to *target*.

        Args:
            target: Domain name of the target.
            http: Shared async HTTP client.
            max_patterns: Maximum number of name patterns to check.

        Returns:
            List of finding dicts with type, url, status, severity.
        """
        findings: List[Dict[str, Any]] = []
        base_name = _strip_domain(target)
        patterns: List[str] = (
            self._patterns.get("azure_blob", {}).get("patterns", [])
        )

        for pattern in patterns[:max_patterns]:
            name = pattern.replace("{target}", base_name)

            # Azure Blob Storage check
            blob_url = f"https://{name}.blob.core.windows.net"
            try:
                resp = await http.get(blob_url, allow_redirects=False)
                status = resp.get("status", 0) if resp else 0
                if status == 200:
                    findings.append({
                        "type": "azure_blob_public",
                        "url": blob_url,
                        "name": name,
                        "status": status,
                        "severity": "high",
                        "description": f"Azure Blob Storage account '{name}' is publicly accessible.",
                    })
                elif status == 403:
                    findings.append({
                        "type": "azure_blob_exists",
                        "url": blob_url,
                        "name": name,
                        "status": status,
                        "severity": "info",
                        "description": f"Azure Blob Storage account '{name}' exists (access denied).",
                    })
            except Exception as exc:  # noqa: BLE001
                logger.debug("Azure blob check failed for %s: %s", blob_url, exc)

            # Azure App Service check
            app_url = f"https://{name}.azurewebsites.net"
            try:
                resp = await http.get(app_url, allow_redirects=True)
                status = resp.get("status", 0) if resp else 0
                if status == 200:
                    findings.append({
                        "type": "azure_app_service",
                        "url": app_url,
                        "name": name,
                        "status": status,
                        "severity": "high",
                        "description": f"Azure App Service '{name}' is publicly accessible.",
                    })
                elif status == 403:
                    findings.append({
                        "type": "azure_app_service_exists",
                        "url": app_url,
                        "name": name,
                        "status": status,
                        "severity": "info",
                        "description": f"Azure App Service '{name}' exists (access denied).",
                    })
            except Exception as exc:  # noqa: BLE001
                logger.debug("Azure app check failed for %s: %s", app_url, exc)

        return findings
