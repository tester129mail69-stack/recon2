"""Pydantic models for the GODRECON REST API.

Defines request/response schemas for all API endpoints.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ScanStatus(str, Enum):
    """Possible scan lifecycle states."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    """Request body for ``POST /api/v1/scan``.

    Attributes:
        target: Domain, IP, or CIDR to scan.
        modules: Optional list of module names to enable.
        config_overrides: Optional flat key=value overrides applied to the
                          loaded configuration before the scan starts.
    """

    target: str = Field(..., description="Domain, IP, or CIDR to scan", examples=["example.com"])
    modules: Optional[List[str]] = Field(
        default=None,
        description="Modules to enable. Defaults to config-defined module set.",
        examples=[["dns", "http_probe", "ssl"]],
    )
    config_overrides: Dict[str, Any] = Field(
        default_factory=dict,
        description="Optional flat config overrides (section.key=value form not required).",
    )


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class FindingResponse(BaseModel):
    """A single finding from a scan module.

    Attributes:
        title: Short finding title.
        description: Detailed description.
        severity: Severity level (info/low/medium/high/critical).
        data: Arbitrary extra data.
        tags: Classification tags.
    """

    title: str
    description: str = ""
    severity: str = "info"
    data: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)


class ScanResponse(BaseModel):
    """Response body for scan creation and status endpoints.

    Attributes:
        scan_id: UUID identifying this scan.
        status: Current scan status.
        target: Scan target.
        progress: Rough progress percentage (0–100).
        created_at: ISO-8601 creation timestamp.
        started_at: ISO-8601 start timestamp, or ``None``.
        finished_at: ISO-8601 finish timestamp, or ``None``.
        modules_completed: Names of modules that have finished.
        error: Top-level error message, if any.
    """

    scan_id: str
    status: ScanStatus
    target: str
    progress: float = 0.0
    created_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    modules_completed: List[str] = Field(default_factory=list)
    error: Optional[str] = None


class ScanResult(BaseModel):
    """Full scan results including findings and per-module data.

    Attributes:
        scan_id: UUID of the scan.
        target: Scan target.
        status: Final scan status.
        findings: All findings across all modules.
        module_results: Raw per-module result data.
        summary: High-level summary counters.
        risk_score: Composite risk score (0–100).
        stats: Timing / module statistics.
    """

    scan_id: str
    target: str
    status: ScanStatus
    findings: List[FindingResponse] = Field(default_factory=list)
    module_results: Dict[str, Any] = Field(default_factory=dict)
    summary: Dict[str, int] = Field(default_factory=dict)
    risk_score: float = 0.0
    stats: Dict[str, Any] = Field(default_factory=dict)


class HealthResponse(BaseModel):
    """Response body for ``GET /api/v1/health``.

    Attributes:
        status: Service status string.
        version: GODRECON version.
        uptime: Seconds since the server started.
    """

    status: str = "ok"
    version: str
    uptime: float


class ModuleInfo(BaseModel):
    """Information about a single scan module.

    Attributes:
        name: Module name.
        description: Module description.
        version: Module version.
        category: Module category.
        enabled: Whether the module is currently enabled in config.
    """

    name: str
    description: str = ""
    version: str = "1.0.0"
    category: str = "general"
    enabled: bool = True
