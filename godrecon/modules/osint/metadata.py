"""Document metadata extraction for GODRECON OSINT."""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_PDF_META_FIELDS = [
    "Author",
    "Creator",
    "Producer",
    "Title",
    "Subject",
    "Keywords",
    "CreationDate",
    "ModDate",
]


class MetadataExtractor:
    """Extract metadata from documents found on a target."""

    def __init__(self, http: AsyncHTTPClient) -> None:
        """Initialise with an existing HTTP client.

        Args:
            http: Shared async HTTP client instance.
        """
        self._http = http

    async def extract(self, url: str) -> Dict[str, Any]:
        """Extract metadata from a document at *url*.

        Performs a HEAD request first to gather HTTP-level metadata, then
        attempts basic PDF metadata extraction from the first 8 KB of
        content (no external libraries required).

        Args:
            url: URL of the document to inspect.

        Returns:
            Dict containing metadata fields that could be extracted.
        """
        meta: Dict[str, Any] = {
            "url": url,
            "content_type": None,
            "last_modified": None,
            "server": None,
            "content_length": None,
            "pdf_metadata": {},
        }

        # Step 1: HEAD request for HTTP headers
        try:
            resp = await self._http.head(url)
            if resp:
                headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
                meta["content_type"] = headers.get("content-type")
                meta["last_modified"] = headers.get("last-modified")
                meta["server"] = headers.get("server")
                meta["content_length"] = headers.get("content-length")
        except Exception as exc:  # noqa: BLE001
            logger.debug("HEAD request failed for %s: %s", url, exc)

        # Step 2: PDF metadata via byte inspection
        content_type = (meta["content_type"] or "").lower()
        if "pdf" in content_type or url.lower().endswith(".pdf"):
            try:
                resp = await self._http.get(
                    url,
                    headers={"Range": "bytes=0-8191"},
                )
                if resp and resp.get("body"):
                    body = resp["body"]
                    meta["pdf_metadata"] = self._extract_pdf_meta(body)
            except Exception as exc:  # noqa: BLE001
                logger.debug("PDF metadata extraction failed for %s: %s", url, exc)

        return meta

    @staticmethod
    def _extract_pdf_meta(content: str) -> Dict[str, str]:
        """Parse PDF metadata fields from raw content bytes/string.

        Looks for ``/<Field> (value)`` patterns in the Info dictionary.

        Args:
            content: Raw PDF content (possibly truncated).

        Returns:
            Dict of metadata field name to value.
        """
        pdf_meta: Dict[str, str] = {}
        for field in _PDF_META_FIELDS:
            pattern = rf"/{field}\s*\(([^)]*)\)"
            match = re.search(pattern, content)
            if match:
                pdf_meta[field] = match.group(1).strip()
        return pdf_meta
