"""HTTP content / directory discovery for GODRECON.

Provides :class:`ContentDiscovery` — a high-concurrency directory brute-forcer
with wildcard detection and backup-file enumeration.
"""

from __future__ import annotations

import asyncio
import secrets
import string
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# Default status codes that indicate a path exists.
_DEFAULT_CODES = {200, 201, 301, 302, 307, 401, 403}

# Backup suffixes to probe for each discovered path.
_BACKUP_SUFFIXES = [".bak", ".old", ".orig", ".save", ".swp", "~", ".backup"]

_DEFAULT_WORDLIST: Path = (
    Path(__file__).parent.parent.parent.parent / "wordlists" / "directories.txt"
)

# Length of the random path used for wildcard detection.
_WILDCARD_PATH_LENGTH = 16


class ContentDiscovery:
    """Directory brute-forcer with wildcard detection and backup enumeration.

    Args:
        http_client: Shared :class:`~godrecon.utils.http_client.AsyncHTTPClient`
            instance.
        concurrency: Maximum simultaneous requests.
        timeout: Per-request timeout in seconds.
        status_codes: Set of HTTP status codes treated as "found".
        wordlist_path: Override path to the wordlist file.
    """

    def __init__(
        self,
        http_client: AsyncHTTPClient,
        concurrency: int = 50,
        timeout: float = 10.0,
        status_codes: Optional[List[int]] = None,
        wordlist_path: Optional[str] = None,
    ) -> None:
        self._http = http_client
        self._concurrency = concurrency
        self._timeout = timeout
        self._status_codes: set = set(status_codes) if status_codes else _DEFAULT_CODES
        self._wordlist_path = wordlist_path

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(
        self,
        base_url: str,
        recursive: bool = False,
        max_depth: int = 2,
    ) -> List[Dict[str, Any]]:
        """Brute-force directories/files beneath *base_url*.

        Args:
            base_url: Root URL to probe (e.g. ``https://example.com``).
            recursive: If ``True``, recurse into discovered directories up to
                *max_depth* levels.
            max_depth: Maximum recursion depth (ignored when *recursive* is
                ``False``).

        Returns:
            List of finding dicts for every path that appears to exist.
        """
        base_url = base_url.rstrip("/")

        # Wildcard detection — abort early if every path returns the same body.
        wildcard_length = await self._detect_wildcard(base_url)
        if wildcard_length is not None:
            logger.info(
                "Wildcard response detected on %s (content-length=%d); "
                "content discovery skipped.",
                base_url,
                wildcard_length,
            )
            return []

        wordlist = self.load_wordlist(self._wordlist_path)
        sem = asyncio.Semaphore(self._concurrency)

        found = await self._probe_all(base_url, wordlist, sem)

        if recursive and max_depth > 1:
            dirs = [r for r in found if r["path"].endswith("/")]
            for entry in dirs:
                sub_url = base_url + entry["path"].rstrip("/")
                sub_found = await ContentDiscovery(
                    http_client=self._http,
                    concurrency=self._concurrency,
                    timeout=self._timeout,
                    status_codes=list(self._status_codes),
                    wordlist_path=self._wordlist_path,
                ).run(sub_url, recursive=True, max_depth=max_depth - 1)
                found.extend(sub_found)

        return found

    async def _probe_path(
        self,
        base_url: str,
        path: str,
        sem: asyncio.Semaphore,
    ) -> Optional[Dict[str, Any]]:
        """Probe a single *path* beneath *base_url*.

        Args:
            base_url: Root URL (no trailing slash).
            path: Path to probe, must start with ``/``.
            sem: Concurrency semaphore.

        Returns:
            Finding dict on success, ``None`` if absent or an error occurred.
        """
        url = base_url + path
        async with sem:
            try:
                start = time.monotonic()
                resp = await self._http.get(
                    url,
                    allow_redirects=False,
                    timeout=self._timeout,
                )
                elapsed = round(time.monotonic() - start, 3)
            except Exception as exc:  # noqa: BLE001
                logger.debug("Probe error for %s: %s", url, exc)
                return None

        status = resp.get("status", -1)
        if status not in self._status_codes:
            return None

        body: str = resp.get("body", "") or ""
        headers: Dict[str, str] = resp.get("headers", {}) or {}
        content_length = int(headers.get("Content-Length", len(body)))
        content_type = headers.get("Content-Type", "")
        redirect_url: Optional[str] = headers.get("Location")

        return {
            "path": path,
            "url": url,
            "status_code": status,
            "content_length": content_length,
            "content_type": content_type,
            "response_time": elapsed,
            "redirect_url": redirect_url,
        }

    async def _detect_wildcard(self, base_url: str) -> Optional[int]:
        """Probe a random path to detect catch-all (wildcard) responses.

        Args:
            base_url: Root URL to check.

        Returns:
            The response ``Content-Length`` if a wildcard is detected,
            ``None`` otherwise.
        """
        random_path = "/" + "".join(secrets.choice(string.ascii_lowercase) for _ in range(_WILDCARD_PATH_LENGTH))
        url = base_url + random_path
        try:
            resp = await self._http.get(url, allow_redirects=False, timeout=self._timeout)
        except Exception:  # noqa: BLE001
            return None

        status = resp.get("status", -1)
        if status in self._status_codes:
            body: str = resp.get("body", "") or ""
            headers: Dict[str, str] = resp.get("headers", {}) or {}
            return int(headers.get("Content-Length", len(body)))
        return None

    async def check_backups(self, url: str) -> List[Dict[str, Any]]:
        """Check backup variants of an existing URL.

        For example, ``/index.php`` is probed as ``/index.php.bak``,
        ``/index.php.old``, etc.

        Args:
            url: Full URL of the existing resource.

        Returns:
            List of finding dicts for discovered backup files.
        """
        sem = asyncio.Semaphore(len(_BACKUP_SUFFIXES))
        # Split base URL and path
        for scheme in ("https://", "http://"):
            if url.startswith(scheme):
                rest = url[len(scheme):]
                slash = rest.find("/")
                if slash == -1:
                    return []
                base_url = scheme + rest[:slash]
                path = rest[slash:]
                break
        else:
            return []

        tasks = [
            asyncio.create_task(
                self._probe_path(base_url, path + suffix, sem)
            )
            for suffix in _BACKUP_SUFFIXES
        ]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]

    # ------------------------------------------------------------------
    # Class methods
    # ------------------------------------------------------------------

    @classmethod
    def load_wordlist(cls, wordlist_path: Optional[str] = None) -> List[str]:
        """Load directory wordlist from file.

        Args:
            wordlist_path: Override path to a plain-text wordlist (one entry
                per line).  Defaults to ``wordlists/directories.txt`` relative
                to the project root.

        Returns:
            List of paths (each prefixed with ``/``).
        """
        resolved = Path(wordlist_path) if wordlist_path else _DEFAULT_WORDLIST
        try:
            lines = resolved.read_text(encoding="utf-8").splitlines()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not load wordlist from %s: %s", resolved, exc)
            return []

        paths: List[str] = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if not line.startswith("/"):
                line = "/" + line
            paths.append(line)
        return paths

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _probe_all(
        self,
        base_url: str,
        wordlist: List[str],
        sem: asyncio.Semaphore,
    ) -> List[Dict[str, Any]]:
        tasks = [
            asyncio.create_task(self._probe_path(base_url, path, sem))
            for path in wordlist
        ]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]
