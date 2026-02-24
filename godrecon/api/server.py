"""FastAPI REST API server for GODRECON.

Exposes all GODRECON scanning functionality over HTTP with optional
API key authentication.  Runs as an independent asyncio service alongside
or instead of the CLI scan engine.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

_SERVER_START_TIME = time.time()

try:
    from fastapi import Depends, FastAPI, HTTPException, Path, status
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
    import uvicorn

    from godrecon import __version__
    from godrecon.api.auth import make_api_key_dependency
    from godrecon.api.models import (
        HealthResponse,
        ModuleInfo,
        ScanRequest,
        ScanResponse,
        ScanResult,
        ScanStatus,
        FindingResponse,
    )
    from godrecon.api.scan_manager import ScanManager

    # ---------------------------------------------------------------------------
    # Application factory
    # ---------------------------------------------------------------------------

    def create_app(
        api_key: str = "",
        cors_origins: Optional[List[str]] = None,
        max_concurrent_scans: int = 3,
    ) -> FastAPI:
        """Build and return a configured FastAPI application.

        Args:
            api_key: Required ``X-API-Key`` value. Empty string disables auth.
            cors_origins: List of allowed CORS origins. Defaults to ``["*"]``.
            max_concurrent_scans: Maximum parallel scans.

        Returns:
            Configured :class:`fastapi.FastAPI` instance.
        """
        _app = FastAPI(
            title="GODRECON API",
            description="REST API for the GODRECON reconnaissance tool",
            version=__version__,
        )

        # CORS
        origins = cors_origins if cors_origins is not None else ["*"]
        _app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

        scan_manager = ScanManager(max_concurrent_scans=max_concurrent_scans)
        auth_dep = make_api_key_dependency(api_key)

        # Attach scan_manager to app state so the dashboard router can access it
        _app.state.scan_manager = scan_manager

        # Mount dashboard router (Jinja2 templates served at /dashboard/*)
        try:
            from godrecon.dashboard.routes import router as dashboard_router
            _app.include_router(dashboard_router)
        except Exception:  # noqa: BLE001
            pass

        # ------------------------------------------------------------------
        # Health / meta
        # ------------------------------------------------------------------

        @_app.get(
            "/api/v1/health",
            response_model=HealthResponse,
            tags=["meta"],
            summary="Health check",
        )
        async def health() -> HealthResponse:
            """Return service health status."""
            return HealthResponse(
                status="ok",
                version=__version__,
                uptime=round(time.time() - _SERVER_START_TIME, 1),
            )

        @_app.get(
            "/api/v1/modules",
            response_model=List[ModuleInfo],
            tags=["meta"],
            summary="List available modules",
            dependencies=[Depends(auth_dep)],
        )
        async def list_modules() -> List[ModuleInfo]:
            """Return metadata for all available scan modules."""
            from godrecon.core.config import load_config
            import importlib
            import pkgutil
            import godrecon.modules as modules_pkg
            from godrecon.modules.base import BaseModule

            cfg = load_config()
            enabled_modules: Dict[str, Any] = cfg.modules.model_dump()
            result: List[ModuleInfo] = []

            for _, modname, ispkg in pkgutil.iter_modules(modules_pkg.__path__):
                if not ispkg:
                    continue
                enabled = enabled_modules.get(modname, True)
                try:
                    pkg = importlib.import_module(f"godrecon.modules.{modname}")
                    cls = _find_module_class(pkg, modname)
                    if cls:
                        result.append(
                            ModuleInfo(
                                name=cls.name,
                                description=cls.description,
                                version=cls.version,
                                category=cls.category,
                                enabled=bool(enabled),
                            )
                        )
                    else:
                        result.append(ModuleInfo(name=modname, enabled=bool(enabled)))
                except Exception:  # noqa: BLE001
                    result.append(ModuleInfo(name=modname, enabled=bool(enabled)))

            return result

        @_app.get(
            "/api/v1/config",
            tags=["meta"],
            summary="Get current configuration",
            dependencies=[Depends(auth_dep)],
        )
        async def get_config() -> Dict[str, Any]:
            """Return the current GODRECON configuration (API keys redacted)."""
            from godrecon.core.config import load_config
            cfg = load_config()
            data = cfg.model_dump()
            # Redact API keys
            if "api_keys" in data:
                data["api_keys"] = {k: "***" if v else "" for k, v in data["api_keys"].items()}
            return data

        # ------------------------------------------------------------------
        # Scan endpoints
        # ------------------------------------------------------------------

        @_app.post(
            "/api/v1/scan",
            response_model=ScanResponse,
            status_code=status.HTTP_202_ACCEPTED,
            tags=["scans"],
            summary="Start a new scan",
            dependencies=[Depends(auth_dep)],
        )
        async def create_scan(request: ScanRequest) -> ScanResponse:
            """Create and immediately start a new scan.

            The scan runs as a background task.  Poll ``GET /api/v1/scan/{scan_id}``
            for progress updates.
            """
            record = scan_manager.create_scan(
                target=request.target,
                modules=request.modules,
                config_overrides=request.config_overrides,
            )
            scan_manager.start_scan(record)
            return record.to_response()

        @_app.get(
            "/api/v1/scans",
            response_model=List[ScanResponse],
            tags=["scans"],
            summary="List all scans",
            dependencies=[Depends(auth_dep)],
        )
        async def list_scans() -> List[ScanResponse]:
            """Return all scan records, most recent first."""
            return [r.to_response() for r in scan_manager.list_scans()]

        @_app.get(
            "/api/v1/scan/{scan_id}",
            response_model=ScanResponse,
            tags=["scans"],
            summary="Get scan status",
            dependencies=[Depends(auth_dep)],
        )
        async def get_scan(scan_id: str = Path(..., description="Scan UUID")) -> ScanResponse:
            """Return the current status and progress of a scan."""
            record = scan_manager.get(scan_id)
            if record is None:
                raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found.")
            return record.to_response()

        @_app.get(
            "/api/v1/scan/{scan_id}/results",
            response_model=ScanResult,
            tags=["scans"],
            summary="Get scan results",
            dependencies=[Depends(auth_dep)],
        )
        async def get_scan_results(
            scan_id: str = Path(..., description="Scan UUID"),
        ) -> ScanResult:
            """Return full scan results including all module data."""
            record = scan_manager.get(scan_id)
            if record is None:
                raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found.")
            return record.to_result()

        @_app.get(
            "/api/v1/scan/{scan_id}/findings",
            response_model=List[FindingResponse],
            tags=["scans"],
            summary="Get findings only",
            dependencies=[Depends(auth_dep)],
        )
        async def get_findings(
            scan_id: str = Path(..., description="Scan UUID"),
        ) -> List[FindingResponse]:
            """Return only the findings from a completed scan."""
            record = scan_manager.get(scan_id)
            if record is None:
                raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found.")
            return record.to_result().findings

        @_app.get(
            "/api/v1/scan/{scan_id}/report/{fmt}",
            tags=["scans"],
            summary="Download scan report",
            dependencies=[Depends(auth_dep)],
        )
        async def get_report(
            scan_id: str = Path(..., description="Scan UUID"),
            fmt: str = Path(..., description="Report format: json/html/csv/md/pdf"),
        ) -> Any:
            """Download scan report in the requested format."""
            record = scan_manager.get(scan_id)
            if record is None:
                raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found.")
            if record.status not in (ScanStatus.COMPLETED, ScanStatus.FAILED):
                raise HTTPException(
                    status_code=409,
                    detail="Scan has not completed yet.",
                )
            result = record.to_result()
            fmt = fmt.lower()
            if fmt == "json":
                return JSONResponse(content=result.model_dump())
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported format {fmt!r}. Use 'json'.",
            )

        @_app.delete(
            "/api/v1/scan/{scan_id}",
            status_code=status.HTTP_204_NO_CONTENT,
            tags=["scans"],
            summary="Cancel or delete a scan",
            dependencies=[Depends(auth_dep)],
        )
        async def delete_scan(
            scan_id: str = Path(..., description="Scan UUID"),
        ) -> None:
            """Cancel a running scan or delete a completed scan record."""
            if not scan_manager.delete(scan_id):
                raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found.")

        return _app

    # Default app instance (no auth, default settings)
    app = create_app()

    # ---------------------------------------------------------------------------
    # Module class discovery helper (internal)
    # ---------------------------------------------------------------------------

    def _find_module_class(pkg: Any, modname: str) -> Optional[Any]:
        """Find the BaseModule subclass exported by a module package.

        Args:
            pkg: Imported package object.
            modname: Module directory name.

        Returns:
            The class or ``None`` if not found.
        """
        import importlib
        from godrecon.modules.base import BaseModule

        for sub in ("runner", "aggregator", "probe", "scanner"):
            try:
                sub_mod = importlib.import_module(f"{pkg.__name__}.{sub}")
                for attr in vars(sub_mod).values():
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, BaseModule)
                        and attr is not BaseModule
                    ):
                        return attr
            except (ModuleNotFoundError, Exception):  # noqa: BLE001
                pass
        for attr in vars(pkg).values():
            if (
                isinstance(attr, type)
                and issubclass(attr, BaseModule)
                and attr is not BaseModule
            ):
                return attr
        return None

    def run_server(
        host: str = "127.0.0.1",
        port: int = 8000,
        api_key: str = "",
        cors_origins: Optional[List[str]] = None,
        max_concurrent_scans: int = 3,
    ) -> None:
        """Start the GODRECON API server.

        Args:
            host: Bind address.
            port: TCP port.
            api_key: Required API key (empty = no auth).
            cors_origins: Allowed CORS origins.
            max_concurrent_scans: Maximum parallel scans.
        """
        server_app = create_app(
            api_key=api_key,
            cors_origins=cors_origins,
            max_concurrent_scans=max_concurrent_scans,
        )
        uvicorn.run(server_app, host=host, port=port)

except ImportError:
    app = None  # type: ignore[assignment]

    def run_server(  # type: ignore[misc]
        host: str = "127.0.0.1",
        port: int = 8000,
        api_key: str = "",
        cors_origins: Optional[List[str]] = None,
        max_concurrent_scans: int = 3,
    ) -> None:
        """Stub: FastAPI/uvicorn not installed."""
        raise RuntimeError(
            "FastAPI and uvicorn are required to run the API server. "
            "Install them with: pip install fastapi uvicorn"
        )
