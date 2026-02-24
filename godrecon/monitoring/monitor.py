"""Main continuous monitoring orchestrator for GODRECON.

Ties together :class:`~godrecon.monitoring.scheduler.ScanScheduler`,
the :class:`~godrecon.core.engine.ScanEngine`,
:class:`~godrecon.monitoring.diff.ScanDiffer`, and
:class:`~godrecon.monitoring.notifications.NotificationManager` to provide
fully automated recurring recon with change-based alerting.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from godrecon.monitoring.diff import ScanDiffer
from godrecon.monitoring.notifications import NotificationManager
from godrecon.monitoring.scheduler import ScanScheduler, ScheduleEntry

logger = logging.getLogger(__name__)


class ContinuousMonitor:
    """Orchestrates continuous monitoring for one or more targets.

    Example::

        from godrecon.core.config import load_config
        monitor = ContinuousMonitor(load_config())
        monitor.add_target("example.com", interval="daily", notify=["slack"])
        await monitor.start()
        # ... runs indefinitely until stopped
        await monitor.stop()
    """

    def __init__(self, config: Any) -> None:
        """Initialise the monitor.

        Args:
            config: Loaded :class:`~godrecon.core.config.Config` instance.
        """
        self._config = config
        storage_dir = Path(getattr(config.monitoring, "storage_dir", "./output/monitoring"))
        storage_dir.mkdir(parents=True, exist_ok=True)
        self._storage_dir = storage_dir

        self._scheduler = ScanScheduler()
        self._differ = ScanDiffer()
        self._notifier = NotificationManager(config.notifications)

    # ------------------------------------------------------------------
    # Schedule management
    # ------------------------------------------------------------------

    def add_target(
        self,
        target: str,
        interval: str = "daily",
        modules: Optional[List[str]] = None,
        notify: Optional[List[str]] = None,
    ) -> ScheduleEntry:
        """Register a target for continuous monitoring.

        Args:
            target: Domain/IP to monitor.
            interval: Scan frequency (``"hourly"``, ``"daily"``, ``"weekly"``,
                      or integer seconds string).
            modules: Optional list of module names to run.
            notify: Notification backend names.

        Returns:
            The created :class:`~godrecon.monitoring.scheduler.ScheduleEntry`.
        """
        return self._scheduler.add(
            target=target,
            interval=interval,
            modules=modules,
            notify=notify,
        )

    def list_targets(self) -> List[ScheduleEntry]:
        """Return all monitored targets.

        Returns:
            List of :class:`~godrecon.monitoring.scheduler.ScheduleEntry` objects.
        """
        return self._scheduler.list_schedules()

    def remove_target(self, schedule_id: str) -> bool:
        """Remove a monitored target by schedule ID.

        Args:
            schedule_id: UUID of the schedule to remove.

        Returns:
            ``True`` if removed.
        """
        return self._scheduler.remove(schedule_id)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start the continuous monitoring loop."""
        logger.info("Starting GODRECON continuous monitor")
        await self._scheduler.start(self._on_schedule_due)

    async def stop(self) -> None:
        """Stop the continuous monitoring loop."""
        logger.info("Stopping GODRECON continuous monitor")
        await self._scheduler.stop()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _on_schedule_due(self, entry: ScheduleEntry) -> None:
        """Handle a schedule that is due for execution.

        Runs the scan, diffs against the previous result, saves the new
        result, and dispatches notifications if changes are detected.

        Args:
            entry: The schedule entry that is due.
        """
        logger.info("Running scheduled scan for %s", entry.target)
        try:
            scan_result = await self._run_scan(entry)
        except Exception:  # noqa: BLE001
            logger.exception("Scan failed for %s", entry.target)
            return

        timestamp = datetime.now(tz=timezone.utc).isoformat()
        result_dict = self._result_to_dict(scan_result)

        old_result = self._load_latest(entry.target)
        diff = self._differ.diff(old_result, result_dict)

        self._save_result(entry.target, result_dict, timestamp)

        if diff.has_changes:
            logger.info(
                "Changes detected for %s: %d new, %d resolved",
                entry.target,
                diff.total_new,
                diff.total_resolved,
            )
            try:
                await self._notifier.notify(
                    target=entry.target,
                    scan_timestamp=timestamp,
                    diff=diff,
                )
            except Exception:  # noqa: BLE001
                logger.exception("Notification failed for %s", entry.target)
        else:
            logger.info("No changes detected for %s", entry.target)

    async def _run_scan(self, entry: ScheduleEntry) -> Any:
        """Execute a scan using the :class:`~godrecon.core.engine.ScanEngine`.

        Args:
            entry: Schedule entry providing target and module overrides.

        Returns:
            :class:`~godrecon.core.engine.ScanResult` instance.
        """
        from godrecon.core.engine import ScanEngine
        import copy

        cfg = copy.deepcopy(self._config)
        if entry.modules:
            # Disable all modules then enable only the requested ones
            for field_name in cfg.modules.model_fields:
                setattr(cfg.modules, field_name, field_name in entry.modules)

        engine = ScanEngine(target=entry.target, config=cfg)
        return await engine.run()

    @staticmethod
    def _result_to_dict(result: Any) -> Dict[str, Any]:
        """Convert a ScanResult to a plain dict suitable for JSON storage.

        Args:
            result: :class:`~godrecon.core.engine.ScanResult` instance.

        Returns:
            Plain dict representation.
        """
        if isinstance(result, dict):
            return result
        data: Dict[str, Any] = {
            "target": getattr(result, "target", ""),
            "started_at": getattr(result, "started_at", None),
            "finished_at": getattr(result, "finished_at", None),
            "stats": getattr(result, "stats", {}),
            "errors": getattr(result, "errors", []),
            "module_results": {},
        }
        module_results = getattr(result, "module_results", {}) or {}
        for mod_name, mod_result in module_results.items():
            if hasattr(mod_result, "model_dump"):
                data["module_results"][mod_name] = mod_result.model_dump()
            elif hasattr(mod_result, "__dict__"):
                data["module_results"][mod_name] = _serialise_module_result(mod_result)
            else:
                data["module_results"][mod_name] = mod_result
        return data

    def _result_path(self, target: str) -> Path:
        """Return the path to a target's latest scan result JSON.

        Args:
            target: Target domain/IP.

        Returns:
            :class:`~pathlib.Path` to the JSON file.
        """
        safe = target.replace("/", "_").replace(":", "_")
        return self._storage_dir / f"{safe}_latest.json"

    def _load_latest(self, target: str) -> Optional[Dict[str, Any]]:
        """Load the most recent scan result for *target* from disk.

        Args:
            target: Target domain/IP.

        Returns:
            Dict or ``None`` if no previous result exists.
        """
        path = self._result_path(target)
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text())
        except Exception:  # noqa: BLE001
            logger.warning("Could not load previous scan for %s", target)
            return None

    def _save_result(
        self,
        target: str,
        result: Dict[str, Any],
        timestamp: str,
    ) -> None:
        """Persist the scan result to disk.

        Args:
            target: Target domain/IP.
            result: Plain dict scan result.
            timestamp: ISO timestamp string (added to the saved data).
        """
        max_history = getattr(self._config.monitoring, "max_history", 100)
        result["_saved_at"] = timestamp

        path = self._result_path(target)
        try:
            path.write_text(json.dumps(result, default=str, indent=2))
        except Exception:  # noqa: BLE001
            logger.warning("Could not save scan result for %s", target)

        # Archive copy
        archive_dir = self._storage_dir / "history" / target.replace("/", "_").replace(":", "_")
        archive_dir.mkdir(parents=True, exist_ok=True)
        archive_path = archive_dir / f"{timestamp.replace(':', '-')}.json"
        try:
            archive_path.write_text(json.dumps(result, default=str, indent=2))
            # Trim history
            history_files = sorted(archive_dir.glob("*.json"))
            while len(history_files) > max_history:
                history_files.pop(0).unlink(missing_ok=True)
        except Exception:  # noqa: BLE001
            logger.warning("Could not archive scan result for %s", target)


def _serialise_module_result(obj: Any) -> Any:
    """Recursively serialise a module result to JSON-compatible types.

    Args:
        obj: Arbitrary object to serialise.

    Returns:
        JSON-compatible value.
    """
    if isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    if isinstance(obj, dict):
        return {k: _serialise_module_result(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_serialise_module_result(v) for v in obj]
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    if hasattr(obj, "__dict__"):
        return {k: _serialise_module_result(v) for k, v in obj.__dict__.items() if not k.startswith("_")}
    return str(obj)
