"""FastAPI REST API server for GODRECON (stub — Phase 3)."""

from __future__ import annotations

from typing import Any, Dict

try:
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
    import uvicorn

    app = FastAPI(
        title="GODRECON API",
        description="REST API for GODRECON reconnaissance tool",
        version="0.1.0",
    )

    @app.get("/health")
    async def health() -> Dict[str, str]:
        """Health check endpoint."""
        return {"status": "ok", "service": "godrecon"}

    @app.get("/version")
    async def version() -> Dict[str, str]:
        """Return API version."""
        from godrecon import __version__
        return {"version": __version__}

    def run_server(host: str = "0.0.0.0", port: int = 8080) -> None:
        """Start the uvicorn ASGI server.

        Args:
            host: Bind address.
            port: TCP port.
        """
        uvicorn.run(app, host=host, port=port)

except ImportError:
    app = None  # type: ignore[assignment]

    def run_server(host: str = "0.0.0.0", port: int = 8080) -> None:
        """Stub: FastAPI/uvicorn not installed."""
        raise RuntimeError(
            "FastAPI and uvicorn are required to run the API server. "
            "Install them with: pip install fastapi uvicorn"
        )
