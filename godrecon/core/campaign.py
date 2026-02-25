"""Multi-target campaign management — scan multiple targets and aggregate results."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class CampaignResult:
    """Aggregated result from a multi-target campaign."""

    name: str
    targets_total: int
    targets_completed: int = 0
    targets_failed: int = 0
    results: dict[str, Any] = field(default_factory=dict)
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    summary: dict = field(default_factory=dict)


class Campaign:
    """Run reconnaissance scans against multiple targets concurrently.

    Args:
        name: Human-readable name for this campaign.
        targets: List of target strings (domains, IPs, CIDRs).
        config: :class:`~godrecon.core.config.Config` instance.
        profile: Optional scan profile name to apply to each target.
    """

    def __init__(
        self,
        name: str,
        targets: list[str],
        config: Any,
        profile: str | None = None,
    ) -> None:
        self.name = name
        self.targets = targets
        self.config = config
        self.profile = profile
        self._event_callbacks: list[Callable[[dict], None]] = []

    # ------------------------------------------------------------------
    # Event system
    # ------------------------------------------------------------------

    def on_event(self, callback: Callable[[dict], None]) -> None:
        """Register an event listener.

        Args:
            callback: Callable that receives an event dict.
        """
        self._event_callbacks.append(callback)

    def _fire(self, event: dict) -> None:
        import contextlib

        for cb in self._event_callbacks:
            with contextlib.suppress(Exception):
                cb(event)

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    async def run(self, max_concurrent: int = 3) -> CampaignResult:
        """Run scans against all targets, limited by *max_concurrent*.

        Args:
            max_concurrent: Maximum number of simultaneous scans.

        Returns:
            :class:`CampaignResult` with aggregated data.
        """
        from godrecon.core.engine import ScanEngine

        result = CampaignResult(name=self.name, targets_total=len(self.targets))
        self._fire({"event": "campaign_started", "name": self.name, "targets": self.targets})

        semaphore = asyncio.Semaphore(max_concurrent)

        async def _scan_one(target: str) -> None:
            async with semaphore:
                self._fire({"event": "target_started", "target": target})
                try:
                    engine = ScanEngine(target=target, config=self.config)
                    if self.profile:
                        from godrecon.core.profiles import apply_profile

                        apply_profile(self.config, self.profile)
                    scan_res = await engine.run()
                    result.results[target] = scan_res
                    result.targets_completed += 1
                    self._fire({"event": "target_finished", "target": target, "status": "ok"})
                except Exception as exc:  # noqa: BLE001
                    result.targets_failed += 1
                    result.results[target] = {"error": str(exc)}
                    self._fire({"event": "target_finished", "target": target, "status": "error", "error": str(exc)})

        await asyncio.gather(*[_scan_one(t) for t in self.targets])

        result.finished_at = time.time()
        result.summary = _build_summary(result.results)
        self._fire({"event": "campaign_finished", "name": self.name, "summary": result.summary})
        return result


def _build_summary(results: dict[str, Any]) -> dict:
    """Build aggregate stats across all targets.

    Args:
        results: Mapping of target string to scan result (ScanResult or error dict).

    Returns:
        Summary dict with totals and ranking.
    """
    sev_totals: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    target_finding_counts: dict[str, int] = {}

    for target, res in results.items():
        count = 0
        if res is None or isinstance(res, dict):
            pass  # error or empty
        else:
            module_results = getattr(res, "module_results", {})
            for mr in module_results.values():
                if mr is None:
                    continue
                findings = getattr(mr, "findings", [])
                count += len(findings)
                for f in findings:
                    sev = getattr(f, "severity", "info").lower()
                    sev_totals[sev] = sev_totals.get(sev, 0) + 1
        target_finding_counts[target] = count

    ranked = sorted(target_finding_counts.items(), key=lambda x: x[1], reverse=True)
    return {
        "findings_by_severity": sev_totals,
        "total_findings": sum(sev_totals.values()),
        "most_vulnerable_targets": [{"target": t, "findings": c} for t, c in ranked],
    }


def load_targets_from_file(filepath: str) -> list[str]:
    """Load a list of targets from a newline-separated text file.

    Lines beginning with ``#`` and blank lines are ignored.

    Args:
        filepath: Path to the target file.

    Returns:
        List of target strings.

    Raises:
        FileNotFoundError: If *filepath* does not exist.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Targets file not found: {filepath}")

    targets: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        targets.append(line)
    return targets
