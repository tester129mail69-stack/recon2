"""Async scan scheduler for GODRECON continuous monitoring.

Provides :class:`ScanScheduler` which manages recurring scan jobs backed by
a JSON file (``godrecon/data/schedules.json`` by default).  All scheduling
is implemented using plain :mod:`asyncio` — no external scheduler library
is required.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Interval helpers
# ---------------------------------------------------------------------------

_INTERVAL_SECONDS: Dict[str, int] = {
    "hourly": 3600,
    "daily": 86400,
    "weekly": 604800,
}


def _parse_interval(interval: str) -> int:
    """Convert an interval string to seconds.

    Accepts ``"hourly"``, ``"daily"``, ``"weekly"``, or a plain integer
    number of seconds as a string.

    Args:
        interval: Human-readable interval name or integer string.

    Returns:
        Number of seconds.

    Raises:
        ValueError: If the interval is not recognised.
    """
    lower = interval.lower().strip()
    if lower in _INTERVAL_SECONDS:
        return _INTERVAL_SECONDS[lower]
    try:
        return int(lower)
    except ValueError:
        pass
    raise ValueError(
        f"Unknown interval {interval!r}. Use 'hourly', 'daily', 'weekly', "
        "or an integer number of seconds."
    )


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class ScheduleEntry:
    """A persisted schedule entry.

    Attributes:
        schedule_id: Unique UUID string.
        target: Scan target domain/IP.
        interval: Interval name or seconds string.
        modules: Optional list of module names.
        notify: Notification backends to use.
        created_at: Unix timestamp of creation.
        last_run: Unix timestamp of last scan (or ``None``).
        next_run: Unix timestamp of next scheduled run.
        enabled: Whether this schedule is active.
    """

    schedule_id: str
    target: str
    interval: str
    modules: List[str] = field(default_factory=list)
    notify: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    last_run: Optional[float] = None
    next_run: float = field(default_factory=time.time)
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain dict for JSON storage.

        Returns:
            Dictionary representation of this entry.
        """
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScheduleEntry":
        """Deserialise from a plain dict.

        Args:
            data: Dictionary loaded from JSON.

        Returns:
            :class:`ScheduleEntry` instance.
        """
        return cls(**data)


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------


class ScanScheduler:
    """Manages recurring scan schedules persisted in a JSON file.

    Example::

        scheduler = ScanScheduler()
        scheduler.add("example.com", interval="daily")
        await scheduler.start(run_callback)
        # ...
        await scheduler.stop()
    """

    def __init__(self, storage_path: Optional[str] = None) -> None:
        """Initialise the scheduler.

        Args:
            storage_path: Path to the JSON file for persisting schedules.
                          Defaults to ``godrecon/data/schedules.json`` relative
                          to the package root.
        """
        if storage_path is None:
            _pkg_root = Path(__file__).parent.parent
            storage_path = str(_pkg_root / "data" / "schedules.json")
        self._path = Path(storage_path)
        self._schedules: Dict[str, ScheduleEntry] = {}
        self._task: Optional[asyncio.Task[None]] = None
        self._running = False
        self._load()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> None:
        """Load schedules from the JSON file."""
        if not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text())
            for entry_data in data.get("schedules", []):
                entry = ScheduleEntry.from_dict(entry_data)
                self._schedules[entry.schedule_id] = entry
        except Exception:  # noqa: BLE001
            logger.warning("Failed to load schedules from %s", self._path, exc_info=True)

    def _save(self) -> None:
        """Persist schedules to the JSON file."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        data = {"schedules": [e.to_dict() for e in self._schedules.values()]}
        self._path.write_text(json.dumps(data, indent=2))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add(
        self,
        target: str,
        interval: str = "daily",
        modules: Optional[List[str]] = None,
        notify: Optional[List[str]] = None,
    ) -> ScheduleEntry:
        """Add a new recurring scan schedule.

        Args:
            target: Domain/IP to scan.
            interval: ``"hourly"``, ``"daily"``, ``"weekly"``, or seconds.
            modules: Optional list of module names to enable.
            notify: Notification backend names to use.

        Returns:
            The created :class:`ScheduleEntry`.
        """
        interval_secs = _parse_interval(interval)
        entry = ScheduleEntry(
            schedule_id=str(uuid.uuid4()),
            target=target,
            interval=interval,
            modules=modules or [],
            notify=notify or [],
            next_run=time.time() + interval_secs,
        )
        self._schedules[entry.schedule_id] = entry
        self._save()
        logger.info("Scheduled %s every %s seconds", target, interval_secs)
        return entry

    def remove(self, schedule_id: str) -> bool:
        """Remove a schedule by ID.

        Args:
            schedule_id: UUID of the schedule to remove.

        Returns:
            ``True`` if removed, ``False`` if not found.
        """
        if schedule_id in self._schedules:
            del self._schedules[schedule_id]
            self._save()
            return True
        return False

    def list_schedules(self) -> List[ScheduleEntry]:
        """Return all schedule entries.

        Returns:
            List of :class:`ScheduleEntry` objects.
        """
        return list(self._schedules.values())

    def get(self, schedule_id: str) -> Optional[ScheduleEntry]:
        """Retrieve a schedule by ID.

        Args:
            schedule_id: UUID string.

        Returns:
            :class:`ScheduleEntry` or ``None``.
        """
        return self._schedules.get(schedule_id)

    async def start(
        self,
        run_callback: Callable[["ScheduleEntry"], Any],
    ) -> None:
        """Start the background scheduling loop.

        Args:
            run_callback: Async or sync callable invoked with a
                          :class:`ScheduleEntry` when it is due.  Any
                          exception raised by the callback is caught and
                          logged.
        """
        self._running = True
        self._task = asyncio.create_task(self._loop(run_callback))

    async def stop(self) -> None:
        """Stop the background scheduling loop."""
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _loop(
        self,
        run_callback: Callable[["ScheduleEntry"], Any],
    ) -> None:
        """Internal scheduling loop.

        Args:
            run_callback: Callable to invoke for due entries.
        """
        while self._running:
            now = time.time()
            for entry in list(self._schedules.values()):
                if not entry.enabled:
                    continue
                if now >= entry.next_run:
                    try:
                        if asyncio.iscoroutinefunction(run_callback):
                            await run_callback(entry)
                        else:
                            run_callback(entry)
                    except Exception:  # noqa: BLE001
                        logger.exception("Error running scheduled scan for %s", entry.target)
                    finally:
                        interval_secs = _parse_interval(entry.interval)
                        entry.last_run = time.time()
                        entry.next_run = entry.last_run + interval_secs
                        self._save()
            # Sleep 30 seconds between polling ticks
            await asyncio.sleep(30)
