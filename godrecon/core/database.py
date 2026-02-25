"""SQLite persistence layer for GODRECON scan results."""

from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


_DEFAULT_DB_PATH = Path.home() / ".godrecon" / "scans.db"

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    result_json TEXT,
    error TEXT,
    started_at REAL,
    finished_at REAL,
    created_at REAL NOT NULL DEFAULT (strftime('%s', 'now'))
);
"""


class ScanStore:
    """SQLite-backed store for GODRECON scan results.

    Uses Python's built-in :mod:`sqlite3` module — no extra dependencies.
    The default database path is ``~/.godrecon/scans.db``, but you can
    override it via the ``GODRECON_DB_PATH`` environment variable or by
    passing ``db_path`` directly.

    Args:
        db_path: Filesystem path to the SQLite database file.  The parent
            directory is created automatically if it does not exist.
    """

    def __init__(self, db_path: str | None = None) -> None:
        path_str = (
            db_path
            or os.environ.get("GODRECON_DB_PATH")
            or str(_DEFAULT_DB_PATH)
        )
        resolved = Path(path_str)
        resolved.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(resolved), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute(_CREATE_TABLE_SQL)
        self._conn.commit()

    # ------------------------------------------------------------------
    # Write operations
    # ------------------------------------------------------------------

    def save_scan(
        self,
        scan_id: str,
        target: str,
        status: str,
        result_json: str,
        started_at: float,
        finished_at: float | None = None,
    ) -> None:
        """Insert or replace a scan record.

        Args:
            scan_id: Unique scan identifier.
            target: Scan target string (domain / IP / CIDR).
            status: Scan status (``pending``, ``running``, ``completed``, ``failed``).
            result_json: JSON-serialised scan result.
            started_at: Unix timestamp when the scan started.
            finished_at: Unix timestamp when the scan finished, or *None*.
        """
        self._conn.execute(
            """
            INSERT OR REPLACE INTO scans
                (scan_id, target, status, result_json, started_at, finished_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                target,
                status,
                result_json,
                started_at,
                finished_at,
                time.time(),
            ),
        )
        self._conn.commit()

    def update_scan_status(
        self,
        scan_id: str,
        status: str,
        error: str | None = None,
        finished_at: float | None = None,
    ) -> None:
        """Update the status (and optional error / finish time) of a scan.

        Args:
            scan_id: Unique scan identifier.
            status: New status string.
            error: Optional error message to persist.
            finished_at: Unix timestamp when the scan finished.
        """
        self._conn.execute(
            """
            UPDATE scans
               SET status = ?, error = ?, finished_at = ?
             WHERE scan_id = ?
            """,
            (status, error, finished_at, scan_id),
        )
        self._conn.commit()

    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan record by *scan_id*.

        Args:
            scan_id: Unique scan identifier.

        Returns:
            ``True`` if a row was deleted, ``False`` if not found.
        """
        cursor = self._conn.execute(
            "DELETE FROM scans WHERE scan_id = ?", (scan_id,)
        )
        self._conn.commit()
        return cursor.rowcount > 0

    # ------------------------------------------------------------------
    # Read operations
    # ------------------------------------------------------------------

    def get_scan(self, scan_id: str) -> Dict[str, Any] | None:
        """Fetch a single scan record by *scan_id*.

        Args:
            scan_id: Unique scan identifier.

        Returns:
            A dict with all scan columns, or *None* if not found.
        """
        row = self._conn.execute(
            "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        return dict(row) if row else None

    def list_scans(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Return recent scans ordered by creation time (newest first).

        Args:
            limit: Maximum number of records to return.

        Returns:
            List of scan record dicts.
        """
        rows = self._conn.execute(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        self._conn.close()

    def __enter__(self) -> "ScanStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
