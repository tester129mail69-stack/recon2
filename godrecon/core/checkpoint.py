"""Scan checkpoint system — save and resume interrupted scans."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


class CheckpointManager:
    """Save and load scan checkpoints so interrupted scans can be resumed.

    Checkpoints are stored as JSON files under *checkpoint_dir*.

    Args:
        scan_id: Unique scan identifier.
        checkpoint_dir: Directory to store checkpoint files.
    """

    def __init__(
        self,
        scan_id: str,
        checkpoint_dir: str = "~/.godrecon/checkpoints/",
    ) -> None:
        self.scan_id = scan_id
        self.checkpoint_dir = Path(checkpoint_dir).expanduser()
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # File path helper
    # ------------------------------------------------------------------

    def _path(self, scan_id: str) -> Path:
        return self.checkpoint_dir / f"{scan_id}.checkpoint.json"

    # ------------------------------------------------------------------
    # Operations
    # ------------------------------------------------------------------

    def save(
        self,
        completed_modules: list[str],
        partial_results: dict,
        config_snapshot: dict | None = None,
        target: str = "",
    ) -> None:
        """Write a checkpoint file.

        Args:
            completed_modules: List of module names that have already finished.
            partial_results: Accumulated results so far.
            config_snapshot: Serialisable snapshot of the scan config.
            target: Scan target string.
        """
        data: dict[str, Any] = {
            "scan_id": self.scan_id,
            "target": target,
            "completed_modules": completed_modules,
            "partial_results": partial_results,
            "timestamp": time.time(),
            "config_snapshot": config_snapshot or {},
        }
        self._path(self.scan_id).write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

    def load(self, scan_id: str) -> dict | None:
        """Load a checkpoint by *scan_id*.

        Args:
            scan_id: The scan identifier to look up.

        Returns:
            Checkpoint dict, or ``None`` if no checkpoint exists.
        """
        p = self._path(scan_id)
        if not p.exists():
            return None
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

    def exists(self, scan_id: str) -> bool:
        """Return ``True`` if a checkpoint file exists for *scan_id*.

        Args:
            scan_id: The scan identifier to check.
        """
        return self._path(scan_id).exists()

    def delete(self, scan_id: str) -> None:
        """Remove the checkpoint file for *scan_id*.

        Args:
            scan_id: The scan identifier whose checkpoint should be deleted.
        """
        p = self._path(scan_id)
        if p.exists():
            p.unlink()

    def list_checkpoints(self) -> list[dict]:
        """List all available checkpoints with their metadata.

        Returns:
            List of dicts, each containing ``scan_id``, ``target``, ``timestamp``,
            and ``completed_modules``.
        """
        checkpoints: list[dict] = []
        for p in sorted(self.checkpoint_dir.glob("*.checkpoint.json")):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                checkpoints.append(
                    {
                        "scan_id": data.get("scan_id", p.stem),
                        "target": data.get("target", ""),
                        "timestamp": data.get("timestamp", 0.0),
                        "completed_modules": data.get("completed_modules", []),
                    }
                )
            except (json.JSONDecodeError, OSError):
                continue
        return checkpoints
