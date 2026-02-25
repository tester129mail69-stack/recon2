"""FastAPI router providing the GODRECON web dashboard.

All dashboard pages are rendered with Jinja2 templates.  The router is
mounted at ``/dashboard`` in the main :func:`~godrecon.api.server.create_app`
factory.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from fastapi import APIRouter, Form, HTTPException, Request
    from fastapi.responses import HTMLResponse, RedirectResponse
    from fastapi.templating import Jinja2Templates

    _TEMPLATES_DIR = Path(__file__).parent / "templates"
    templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

    router = APIRouter(prefix="/dashboard", tags=["dashboard"])

    def _get_scan_manager(request: Request) -> Any:
        return getattr(request.app.state, "scan_manager", None)

    def _get_all_scans(scan_manager: Any) -> List[Dict[str, Any]]:
        if scan_manager is None:
            return []
        records = scan_manager.list_scans()
        return [_record_to_dict(r) for r in records]

    def _record_to_dict(record: Any) -> Dict[str, Any]:
        resp = record.to_response()
        findings_count = 0
        risk_score = 0.0
        status_val = resp.status.value if hasattr(resp.status, "value") else str(resp.status)
        if status_val == "completed":
            try:
                result = record.to_result()
                findings_count = len(result.findings)
            except Exception:
                pass
        return {
            "scan_id": resp.scan_id,
            "target": resp.target,
            "status": resp.status.value if hasattr(resp.status, "value") else str(resp.status),
            "created_at": resp.created_at.isoformat() if resp.created_at else "",
            "started_at": resp.started_at.isoformat() if resp.started_at else None,
            "finished_at": resp.finished_at.isoformat() if resp.finished_at else None,
            "modules_completed": resp.modules_completed,
            "error": resp.error,
            "findings_count": findings_count,
            "risk_score": risk_score,
        }

    def _get_findings_for_scan(scan_manager: Any, scan_id: str) -> List[Dict[str, Any]]:
        if scan_manager is None:
            return []
        record = scan_manager.get(scan_id)
        if record is None:
            return []
        try:
            result = record.to_result()
            return [
                {
                    "title": getattr(f, "title", ""),
                    "severity": getattr(f, "severity", "info"),
                    "category": getattr(f, "category", ""),
                    "description": getattr(f, "description", ""),
                    "target": getattr(f, "target", ""),
                    "module": getattr(f, "module", ""),
                    "evidence": getattr(f, "evidence", ""),
                    "remediation": getattr(f, "remediation", ""),
                }
                for f in result.findings
            ]
        except Exception:
            return []

    def _load_config_for_display() -> Dict[str, Any]:
        try:
            from godrecon.core.config import load_config
            cfg = load_config()
            data = cfg.model_dump()
            if "api_keys" in data:
                data["api_keys"] = {k: "***" if v else "" for k, v in data["api_keys"].items()}
            return data
        except Exception:
            return {}

    @router.get("/", response_class=HTMLResponse, summary="Dashboard home")
    async def dashboard_home(request: Request) -> HTMLResponse:
        scan_manager = _get_scan_manager(request)
        scans = _get_all_scans(scan_manager)
        recent = scans[:5]
        total_scans = len(scans)
        active_scans = sum(1 for s in scans if s["status"] in ("running", "pending"))
        total_findings = sum(s["findings_count"] for s in scans)
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "recent_scans": recent,
                "total_scans": total_scans,
                "active_scans": active_scans,
                "total_findings": total_findings,
            },
        )

    @router.get("/scans", response_class=HTMLResponse, summary="Scan history")
    async def dashboard_scans(request: Request) -> HTMLResponse:
        scan_manager = _get_scan_manager(request)
        scans = _get_all_scans(scan_manager)
        return templates.TemplateResponse(
            "scans.html",
            {"request": request, "scans": scans},
        )

    @router.get("/scans/{scan_id}", response_class=HTMLResponse, summary="Scan detail")
    async def dashboard_scan_detail(request: Request, scan_id: str) -> HTMLResponse:
        scan_manager = _get_scan_manager(request)
        if scan_manager is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        record = scan_manager.get(scan_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")
        scan = _record_to_dict(record)
        findings = _get_findings_for_scan(scan_manager, scan_id)
        module_breakdown: List[Dict[str, Any]] = []
        try:
            result = record.to_result()
            for mod_name, mod_result in (result.module_results or {}).items():
                count = 0
                if isinstance(mod_result, dict):
                    count = mod_result.get("findings_count", 0)
                elif hasattr(mod_result, "findings_count"):
                    count = mod_result.findings_count or 0
                elif hasattr(mod_result, "findings"):
                    count = len(mod_result.findings or [])
                module_breakdown.append({"module": mod_name, "findings": count})
        except Exception:
            pass
        return templates.TemplateResponse(
            "scan_detail.html",
            {
                "request": request,
                "scan": scan,
                "findings": findings,
                "module_breakdown": module_breakdown,
            },
        )

    @router.get("/findings", response_class=HTMLResponse, summary="Findings browser")
    async def dashboard_findings(
        request: Request,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        module: Optional[str] = None,
        target: Optional[str] = None,
    ) -> HTMLResponse:
        scan_manager = _get_scan_manager(request)
        all_findings: List[Dict[str, Any]] = []
        if scan_manager is not None:
            for record in scan_manager.list_scans():
                scan_findings = _get_findings_for_scan(scan_manager, record.scan_id)
                for f in scan_findings:
                    f["scan_id"] = record.scan_id
                    f["scan_target"] = record.target
                all_findings.extend(scan_findings)
        if severity:
            all_findings = [f for f in all_findings if f["severity"].lower() == severity.lower()]
        if category:
            all_findings = [f for f in all_findings if f["category"].lower() == category.lower()]
        if module:
            all_findings = [f for f in all_findings if f["module"].lower() == module.lower()]
        if target:
            all_findings = [f for f in all_findings if target.lower() in f.get("scan_target", "").lower()]
        return templates.TemplateResponse(
            "findings.html",
            {
                "request": request,
                "findings": all_findings,
                "filters": {
                    "severity": severity,
                    "category": category,
                    "module": module,
                    "target": target,
                },
            },
        )

    @router.get("/surface", response_class=HTMLResponse, summary="Attack surface map")
    async def dashboard_surface(request: Request) -> HTMLResponse:
        scan_manager = _get_scan_manager(request)
        surface_data: Dict[str, Any] = {
            "subdomains": [],
            "ips": [],
            "ports": [],
            "technologies": [],
        }
        if scan_manager is not None:
            for record in scan_manager.list_scans():
                status_val = record.status.value if hasattr(record.status, "value") else str(record.status)
                if status_val != "completed":
                    continue
                try:
                    result = record.to_result()
                    mod_results = result.module_results or {}
                    sub_res = mod_results.get("subdomains")
                    if sub_res:
                        data = getattr(sub_res, "data", None) or (sub_res.get("data") if isinstance(sub_res, dict) else None) or {}
                        subs = data.get("subdomains", []) if isinstance(data, dict) else []
                        for s in subs:
                            if s not in surface_data["subdomains"]:
                                surface_data["subdomains"].append(s)
                    tech_res = mod_results.get("tech")
                    if tech_res:
                        data = getattr(tech_res, "data", None) or (tech_res.get("data") if isinstance(tech_res, dict) else None) or {}
                        if isinstance(data, dict):
                            for url_data in data.values():
                                if isinstance(url_data, dict):
                                    for tech in url_data.get("technologies", []):
                                        if tech not in surface_data["technologies"]:
                                            surface_data["technologies"].append(tech)
                except Exception:
                    pass
        return templates.TemplateResponse(
            "surface.html",
            {"request": request, "surface_data": surface_data},
        )

    @router.get("/settings", response_class=HTMLResponse, summary="Settings page")
    async def dashboard_settings(request: Request) -> HTMLResponse:
        config_data = _load_config_for_display()
        return templates.TemplateResponse(
            "settings.html",
            {"request": request, "config": config_data},
        )

    @router.post("/settings", response_class=HTMLResponse, summary="Save settings")
    async def dashboard_settings_save(request: Request) -> HTMLResponse:
        config_data = _load_config_for_display()
        return templates.TemplateResponse(
            "settings.html",
            {
                "request": request,
                "config": config_data,
                "message": "Settings noted. Update config.yaml to persist changes.",
            },
        )

except ImportError:
    from unittest.mock import MagicMock
    router = MagicMock()  # type: ignore[assignment]
