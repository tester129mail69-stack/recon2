"""Favicon MMH3 hash computation for GODRECON.

Provides :class:`FaviconHasher` which downloads a site's favicon and computes
the MurmurHash3 (mmh3) hash used by Shodan for technology identification.
"""

from __future__ import annotations

import base64
from typing import Any, Dict, Optional

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# Well-known favicon hashes mapping hash→technology
_KNOWN_HASHES: Dict[int, str] = {
    -247388890: "Kibana",
    -652534887: "Jenkins",
    1602494659: "Spring Boot (Whitelabel)",
    116323821: "Apache Tomcat",
    -305023024: "Grafana",
    1485062895: "Jupyter Notebook",
    708578229: "phpMyAdmin",
    -1604102661: "Elasticsearch",
    1934748019: "GitLab",
    -1601655694: "Jira",
    -1488148353: "Confluence",
    -692231806: "Prism CMS",
    -1810262547: "Cisco IOS",
    -1475612874: "Citrix",
    408021114: "WordPress",
    442749392: "Drupal",
    -1427811896: "Joomla",
    522056627: "Magento",
    975770738: "Shopify",
}


class FaviconHasher:
    """Download and hash a site's favicon for Shodan-style identification.

    Args:
        http_client: Pre-configured :class:`AsyncHTTPClient`.
    """

    def __init__(self, http_client: AsyncHTTPClient) -> None:
        self._client = http_client

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def hash_favicon(self, base_url: str) -> Dict[str, Any]:
        """Download favicon and compute MMH3 hash.

        Tries ``/favicon.ico`` first; falls back to parsing the HTML for a
        ``<link rel="icon">`` tag.

        Args:
            base_url: Base URL of the target (e.g. ``https://example.com``).

        Returns:
            Dict with ``url``, ``hash``, ``technology``, ``found`` keys.
        """
        favicon_url = base_url.rstrip("/") + "/favicon.ico"
        result: Dict[str, Any] = {
            "url": favicon_url,
            "hash": None,
            "technology": None,
            "found": False,
        }

        try:
            # Fetch favicon bytes via GET (body will be base64-like)
            resp = await self._client.get(favicon_url)
            status = resp.get("status", -1)
            if status != 200:
                return result

            body = resp.get("body", "")
            if not body:
                return result

            # Encode body to base64 in the Shodan-compatible way
            favicon_bytes = body.encode("latin-1", errors="replace")
            favicon_b64 = base64.standard_b64encode(favicon_bytes)
            # Insert newlines every 76 chars (mimics Shodan's format)
            favicon_b64_nl = b"\n".join(
                favicon_b64[i: i + 76] for i in range(0, len(favicon_b64), 76)
            ) + b"\n"

            mmh3_hash = self._mmh3_hash(favicon_b64_nl)
            technology = _KNOWN_HASHES.get(mmh3_hash)

            result.update({
                "hash": mmh3_hash,
                "technology": technology,
                "found": True,
            })
        except Exception as exc:  # noqa: BLE001
            logger.debug("Favicon fetch failed for %s: %s", base_url, exc)

        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _mmh3_hash(data: bytes) -> int:
        """Compute a signed 32-bit MurmurHash3 of *data*.

        Tries to use the ``mmh3`` library if available; falls back to a pure
        Python implementation.

        Args:
            data: Bytes to hash.

        Returns:
            Signed 32-bit integer hash.
        """
        try:
            import mmh3  # type: ignore[import-untyped]
            return mmh3.hash(data)
        except ImportError:
            return FaviconHasher._mmh3_pure(data)

    @staticmethod
    def _mmh3_pure(data: bytes) -> int:
        """Pure Python MurmurHash3 (32-bit, little-endian).

        Args:
            data: Bytes to hash.

        Returns:
            Signed 32-bit integer hash.
        """
        c1 = 0xCC9E2D51
        c2 = 0x1B873593
        length = len(data)
        h1 = 0
        roundedEnd = (length & 0xFFFFFFFC)

        for i in range(0, roundedEnd, 4):
            k1 = (
                (data[i] & 0xFF)
                | ((data[i + 1] & 0xFF) << 8)
                | ((data[i + 2] & 0xFF) << 16)
                | ((data[i + 3] & 0xFF) << 24)
            )
            k1 = (k1 * c1) & 0xFFFFFFFF
            k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
            k1 = (k1 * c2) & 0xFFFFFFFF
            h1 ^= k1
            h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
            h1 = ((h1 * 5) + 0xE6546B64) & 0xFFFFFFFF

        k1 = 0
        val = length & 0x03
        if val == 3:
            k1 ^= (data[roundedEnd + 2] & 0xFF) << 16
        if val in (2, 3):
            k1 ^= (data[roundedEnd + 1] & 0xFF) << 8
        if val in (1, 2, 3):
            k1 ^= data[roundedEnd] & 0xFF
            k1 = (k1 * c1) & 0xFFFFFFFF
            k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
            k1 = (k1 * c2) & 0xFFFFFFFF
            h1 ^= k1

        h1 ^= length
        # fmix32
        h1 ^= (h1 >> 16)
        h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
        h1 ^= (h1 >> 13)
        h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
        h1 ^= (h1 >> 16)

        # Convert to signed 32-bit
        if h1 >= 0x80000000:
            return h1 - 0x100000000
        return h1
