"""Service fingerprinting for GODRECON port scanning.

Combines well-known port/service mappings from ``services.json`` with
regex-based banner analysis to identify running software and versions.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Optional

_DATA_PATH = Path(__file__).parent.parent.parent / "data" / "services.json"

# Banner parsing patterns: (product_re, version_re)
_SSH_RE = re.compile(r"SSH-[\d.]+-(\S+?)_([\d.]+\S*)", re.IGNORECASE)
_HTTP_SERVER_RE = re.compile(r"Server:\s*(\S+?)/([\d.]+\S*)", re.IGNORECASE)
_FTP_RE = re.compile(r"220[- ].*?(\w+ftpd?|proftpd|vsftpd|filezilla\S*)\s+([\d.]+\S*)", re.IGNORECASE)
_REDIS_VERSION_RE = re.compile(r"redis_version:([\d.]+)", re.IGNORECASE)
_GENERIC_VERSION_RE = re.compile(r"[\d]+\.[\d]+\.[\d]+")

_UNKNOWN_SERVICE: Dict[str, str] = {
    "service": "unknown",
    "protocol": "tcp",
    "description": "",
}

# Number of bytes to scan in MySQL handshake for version string detection.
_MYSQL_VERSION_BANNER_LENGTH = 64


class ServiceFingerprinter:
    """Identify services and extract version information from port banners.

    Args:
        services_data: Pre-loaded mapping of port strings to service dicts.
                       When ``None``, an empty mapping is used and
                       :meth:`get_service` returns ``unknown`` for every port.
    """

    def __init__(self, services_data: Optional[Dict[str, Any]] = None) -> None:
        self._services: Dict[str, Any] = services_data or {}

    # ------------------------------------------------------------------
    # Service lookup
    # ------------------------------------------------------------------

    def get_service(self, port: int) -> Dict[str, str]:
        """Return service metadata for *port*.

        Args:
            port: TCP port number.

        Returns:
            Dict with ``"service"``, ``"protocol"``, and ``"description"`` keys.
            Falls back to ``"unknown"`` when the port is not in the data set.
        """
        entry = self._services.get(str(port))
        if not entry:
            return dict(_UNKNOWN_SERVICE)
        return {
            "service": entry.get("service", "unknown"),
            "protocol": entry.get("protocol", "tcp"),
            "description": entry.get("description", ""),
        }

    # ------------------------------------------------------------------
    # Full fingerprint
    # ------------------------------------------------------------------

    def fingerprint(self, port: int, banner: Optional[str]) -> Dict[str, Any]:
        """Combine port-service lookup with banner analysis.

        Args:
            port: TCP port number.
            banner: Optional banner string captured from the service.

        Returns:
            Dict with keys: ``port``, ``service``, ``protocol``,
            ``description``, ``banner``, ``version``, ``product``,
            ``extra_info``.
        """
        svc = self.get_service(port)
        result: Dict[str, Any] = {
            "port": port,
            "service": svc["service"],
            "protocol": svc["protocol"],
            "description": svc["description"],
            "banner": banner or "",
            "version": "",
            "product": "",
            "extra_info": "",
        }

        if banner:
            self._extract_version(port, banner, result)

        return result

    # ------------------------------------------------------------------
    # Class method factory
    # ------------------------------------------------------------------

    @classmethod
    def load_services(cls, data_path: Optional[str] = None) -> "ServiceFingerprinter":
        """Create a :class:`ServiceFingerprinter` loaded from ``services.json``.

        Args:
            data_path: Optional override path.  Uses the bundled data file
                       when not provided.

        Returns:
            Configured :class:`ServiceFingerprinter` instance.
        """
        path = Path(data_path) if data_path else _DATA_PATH
        try:
            with path.open("r") as fh:
                data = json.load(fh)
        except Exception:  # noqa: BLE001
            data = {}
        return cls(services_data=data)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_version(port: int, banner: str, result: Dict[str, Any]) -> None:
        """Populate ``version``, ``product``, and ``extra_info`` in *result*.

        Args:
            port: Destination port — guides which pattern to try first.
            banner: Raw banner text.
            result: Fingerprint dict to mutate in-place.
        """
        # SSH: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
        m = _SSH_RE.search(banner)
        if m:
            result["product"] = m.group(1)
            result["version"] = m.group(2)
            return

        # HTTP Server header: "Server: Apache/2.4.41 (Ubuntu)"
        m = _HTTP_SERVER_RE.search(banner)
        if m:
            result["product"] = m.group(1)
            result["version"] = m.group(2)
            return

        # FTP banner: "220 vsftpd 3.0.3"
        m = _FTP_RE.search(banner)
        if m:
            result["product"] = m.group(1)
            result["version"] = m.group(2)
            return

        # MySQL: banner is already decoded; the server version string (e.g. "8.0.28")
        # appears in the early portion of the decoded handshake text.
        if port == 3306 and banner:
            m = _GENERIC_VERSION_RE.search(banner[:_MYSQL_VERSION_BANNER_LENGTH])
            if m:
                result["product"] = "MySQL"
                result["version"] = m.group(0)
                return

        # Redis INFO or PONG
        if port == 6379:
            m = _REDIS_VERSION_RE.search(banner)
            if m:
                result["product"] = "Redis"
                result["version"] = m.group(1)
                return
            if banner.startswith("+PONG"):
                result["product"] = "Redis"
                return

        # Generic three-part version fallback
        m = _GENERIC_VERSION_RE.search(banner)
        if m:
            result["version"] = m.group(0)
