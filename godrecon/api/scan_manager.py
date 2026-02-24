"""Scan lifecycle manager for the GODRECON REST API.

Manages the creation, execution, monitoring, and cancellation of scans.
All state is kept in memory (no database required).
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from godrecon.api.models import FindingResponse, ScanResponse, ScanResult, ScanStatus
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)


def _utcnow() -> datetime:
    """Return timezone-aware current UTC time."""
    return datetime.now(tz=timezone.utc)


class ScanRecord:
    """Internal state for a single scan.

    Attributes:
        scan_id: UUID string.
        target: Scan target.
        modules: Optional list of enabled module names.
        config_overrides: Configuration overrides.
        status: Current lifecycle status.
        created_at: Creation timestamp.
        started_at: Start timestamp (or ``None``).
        finished_at: Finish timestamp (or ``None``).
        modules_completed: Names of completed modules.
        error: Top-level error message (or ``None``).
        _engine_result: Raw ScanResult from the engine.
        _task: asyncio Task running the scan.
    """

    def __init__(
        self,
        target: str,
        modules: Optional[List[str]] = None,
        config_overrides: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.scan_id: str = str(uuid.uuid4())
        self.target = target
        self.modules = modules
        self.config_overrides: Dict[str, Any] = config_overrides or {}
        self.status = ScanStatus.PENDING
        self.created_at: datetime = _utcnow()
        self.started_at: Optional[datetime] = None
        self.finished_at: Optional[datetime] = None
        self.modules_completed: List[str] = []
        self.error: Optional[str] = None
        self._engine_result: Optional[Any] = None
        self._task: Optional["asyncio.Task[None]"] = None

    def to_response(self) -> ScanResponse:
        """Build a :class:`ScanResponse` from this record.

        Returns:
            Serialisable API response model.
        """
        return ScanResponse(
            scan_id=self.scan_id,
            status=self.status,
            target=self.target,
            created_at=self.created_at,
            started_at=self.started_at,
            finished_at=self.finished_at,
            modules_completed=list(self.modules_completed),
            error=self.error,
        )

    def to_result(self) -> ScanResult:
        """Build a full :class:`ScanResult` including findings.

        Returns:
            Serialisable scan result model.
        """
        findings: List[FindingResponse] = []
        module_results: Dict[str, Any] = {}
        stats: Dict[str, Any] = {}

        if self._engine_result is not None:
            eng = self._engine_result
            stats = getattr(eng, "stats", {})
            for mod_name, mod_result in (getattr(eng, "module_results", {}) or {}).items():
                if mod_result is None:
                    continue
                module_results[mod_name] = {
                    "error": mod_result.error,
                    "duration": mod_result.duration,
                    "findings_count": len(mod_result.findings),
                }
                for f in mod_result.findings:
                    findings.append(
                        FindingResponse(
                            title=f.title,
                            description=f.description,
                            severity=f.severity,
                            data=f.data,
                            tags=f.tags,
                        )
                    )

        summary = _build_summary(findings)
        risk_score = _compute_risk_score(findings)

        return ScanResult(
            scan_id=self.scan_id,
            target=self.target,
            status=self.status,
            findings=findings,
            module_results=module_results,
            summary=summary,
            risk_score=risk_score,
            stats=stats,
        )


class ScanManager:
    """Manages the full lifecycle of GODRECON scans.

    Scans are stored in an in-memory dictionary keyed by UUID.

    Args:
        max_concurrent_scans: Maximum number of scans that may run in parallel.
    """

    def __init__(self, max_concurrent_scans: int = 3) -> None:
        self._scans: Dict[str, ScanRecord] = {}
        self._semaphore = asyncio.Semaphore(max_concurrent_scans)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_scan(
        self,
        target: str,
        modules: Optional[List[str]] = None,
        config_overrides: Optional[Dict[str, Any]] = None,
    ) -> ScanRecord:
        """Create a new scan record and return it (not yet started).

        Args:
            target: Domain, IP, or CIDR.
            modules: Optional list of module names to enable.
            config_overrides: Optional configuration overrides.

        Returns:
            New :class:`ScanRecord`.
        """
        record = ScanRecord(
            target=target,
            modules=modules,
            config_overrides=config_overrides,
        )
        self._scans[record.scan_id] = record
        logger.info("Scan created: %s → %s", record.scan_id, target)
        return record

    def start_scan(self, record: ScanRecord) -> None:
        """Schedule the scan to run as a background asyncio task.

        Args:
            record: The scan record to start.
        """
        record._task = asyncio.create_task(self._run(record))

    def get(self, scan_id: str) -> Optional[ScanRecord]:
        """Retrieve a scan record by ID.

        Args:
            scan_id: UUID string.

        Returns:
            :class:`ScanRecord` or ``None`` if not found.
        """
        return self._scans.get(scan_id)

    def list_scans(self) -> List[ScanRecord]:
        """Return all scan records, most recent first.

        Returns:
            List of :class:`ScanRecord` objects.
        """
        return sorted(
            self._scans.values(),
            key=lambda r: r.created_at,
            reverse=True,
        )

    def cancel(self, scan_id: str) -> bool:
        """Cancel a running scan.

        Args:
            scan_id: UUID of the scan to cancel.

        Returns:
            ``True`` if cancelled, ``False`` if not found or already done.
        """
        record = self._scans.get(scan_id)
        if record is None:
            return False
        if record._task and not record._task.done():
            record._task.cancel()
        record.status = ScanStatus.CANCELLED
        record.finished_at = _utcnow()
        return True

    def delete(self, scan_id: str) -> bool:
        """Delete a scan record.

        Args:
            scan_id: UUID of the scan to delete.

        Returns:
            ``True`` if deleted, ``False`` if not found.
        """
        if scan_id not in self._scans:
            return False
        record = self._scans.pop(scan_id)
        if record._task and not record._task.done():
            record._task.cancel()
        return True

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _run(self, record: ScanRecord) -> None:
        """Execute the scan engine for *record* under the concurrency semaphore.

        Args:
            record: Scan record to execute.
        """
        async with self._semaphore:
            record.status = ScanStatus.RUNNING
            record.started_at = _utcnow()
            logger.info("Scan started: %s → %s", record.scan_id, record.target)

            try:
                from godrecon.core.config import load_config
                from godrecon.core.engine import ScanEngine

                cfg = load_config()

                # Apply module list overrides
                if record.modules is not None:
                    for field_name in cfg.modules.model_fields:
                        setattr(cfg.modules, field_name, field_name in record.modules)

                engine = ScanEngine(target=record.target, config=cfg)

                def _on_event(event: Dict[str, Any]) -> None:
                    if event.get("event") == "module_finished":
                        mod = event.get("module", "")
                        if mod and mod not in record.modules_completed:
                            record.modules_completed.append(mod)

                engine.on_event(_on_event)
                engine_result = await engine.run()

                record._engine_result = engine_result
                record.status = ScanStatus.COMPLETED
                logger.info(
                    "Scan completed: %s — %d modules",
                    record.scan_id,
                    len(record.modules_completed),
                )

            except asyncio.CancelledError:
                record.status = ScanStatus.CANCELLED
                logger.info("Scan cancelled: %s", record.scan_id)
            except Exception as exc:  # noqa: BLE001
                record.status = ScanStatus.FAILED
                record.error = str(exc)
                logger.error("Scan failed: %s — %s", record.scan_id, exc)
            finally:
                record.finished_at = _utcnow()


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _build_summary(findings: List[FindingResponse]) -> Dict[str, int]:
    """Build a severity-count summary from a list of findings.

    Args:
        findings: List of finding response objects.

    Returns:
        Dictionary mapping severity → count.
    """
    summary: Dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "total": len(findings),
    }
    for f in findings:
        sev = f.severity.lower()
        if sev in summary:
            summary[sev] += 1
    return summary


def _compute_risk_score(findings: List[FindingResponse]) -> float:
    """Compute a composite risk score (0–100) from findings.

    Args:
        findings: List of finding response objects.

    Returns:
        Float risk score capped at 100.
    """
    weights = {"critical": 15, "high": 8, "medium": 4, "low": 2, "info": 0}
    score = sum(weights.get(f.severity.lower(), 0) for f in findings)
    return min(float(score), 100.0)
