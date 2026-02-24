"""Sensitive file and path checker for GODRECON HTTP content discovery.

Probes a web target for commonly exposed sensitive paths such as environment
files, version-control artefacts, credentials, and debug endpoints.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# HTTP status codes that indicate a path exists (not a generic 404).
_PRESENT_CODES = {200, 201, 301, 302, 307, 401, 403, 500}

_DEFAULT_DATA_PATH: Path = (
    Path(__file__).parent.parent.parent / "data" / "sensitive_paths.json"
)


class SensitiveFileChecker:
    """Check a web target for exposed sensitive files and paths.

    Args:
        http_client: Shared :class:`~godrecon.utils.http_client.AsyncHTTPClient`
            instance (must already be open / used as context manager externally).
        timeout: Per-request timeout in seconds.
        concurrency: Maximum number of simultaneous requests.
    """

    def __init__(
        self,
        http_client: AsyncHTTPClient,
        timeout: float = 10.0,
        concurrency: int = 30,
    ) -> None:
        self._http = http_client
        self._timeout = timeout
        self._concurrency = concurrency

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def check(self, base_url: str) -> List[Dict[str, Any]]:
        """Check all sensitive paths against *base_url*.

        Args:
            base_url: Root URL to probe (e.g. ``https://example.com``).

        Returns:
            List of finding dicts for every path that appears to exist.
        """
        base_url = base_url.rstrip("/")
        paths = self.load_paths()
        sem = asyncio.Semaphore(self._concurrency)

        tasks = [
            asyncio.create_task(self._bounded_check(sem, base_url, entry))
            for entry in paths
        ]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]

    async def check_path(
        self,
        base_url: str,
        path: str,
        metadata: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Probe a single *path* beneath *base_url*.

        Args:
            base_url: Root URL (no trailing slash).
            path: Path to append, must start with ``/``.
            metadata: Dict containing at least ``description``, ``severity``,
                and ``category`` keys from the data file.

        Returns:
            Finding dict on success, or ``None`` if the path is absent / an
            error occurred.
        """
        url = base_url + path
        try:
            start = time.monotonic()
            resp = await self._http.get(
                url,
                allow_redirects=False,
                timeout=self._timeout,
            )
            elapsed = round(time.monotonic() - start, 3)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Sensitive-file check error for %s: %s", url, exc)
            return None

        status = resp.get("status", -1)
        if status not in _PRESENT_CODES:
            return None

        body: str = resp.get("body", "") or ""
        headers: Dict[str, str] = resp.get("headers", {}) or {}
        content_length = int(headers.get("Content-Length", len(body)))

        return {
            "path": path,
            "url": url,
            "status_code": status,
            "content_length": content_length,
            "description": metadata.get("description", ""),
            "severity": metadata.get("severity", "info"),
            "category": metadata.get("category", ""),
            "response_time": elapsed,
        }

    # ------------------------------------------------------------------
    # Class methods
    # ------------------------------------------------------------------

    @classmethod
    def load_paths(cls, data_path: Optional[str] = None) -> List[Dict[str, Any]]:
        """Load sensitive path entries from the data file.

        Args:
            data_path: Override path to the JSON data file.  Defaults to
                the bundled ``godrecon/data/sensitive_paths.json``.

        Returns:
            List of dicts each containing ``path``, ``description``,
            ``severity``, and ``category``.
        """
        resolved = Path(data_path) if data_path else _DEFAULT_DATA_PATH
        try:
            with resolved.open("r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not load sensitive paths from %s: %s", resolved, exc)
            return []

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _bounded_check(
        self,
        sem: asyncio.Semaphore,
        base_url: str,
        entry: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        async with sem:
            return await self.check_path(base_url, entry["path"], entry)
