"""Simple API key authentication for the GODRECON REST API.

An API key is supplied via the ``X-API-Key`` HTTP header.
When the configured key is empty (default), authentication is disabled.
"""

from __future__ import annotations

from typing import Optional

try:
    from fastapi import HTTPException, Security, status
    from fastapi.security.api_key import APIKeyHeader

    _api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

    def make_api_key_dependency(api_key: str):
        """Build a FastAPI dependency that validates the ``X-API-Key`` header.

        Args:
            api_key: The expected secret API key.  If empty, all requests are
                     allowed through without a key.

        Returns:
            An async FastAPI dependency callable.
        """
        async def _check_api_key(
            provided_key: Optional[str] = Security(_api_key_header),
        ) -> None:
            if not api_key:
                # Auth disabled
                return
            if provided_key != api_key:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or missing API key.",
                    headers={"WWW-Authenticate": "ApiKey"},
                )

        return _check_api_key

except ImportError:
    # FastAPI not available — provide no-op stubs so the rest of the code
    # can still import this module without crashing.

    def make_api_key_dependency(api_key: str):  # type: ignore[misc]
        """No-op stub when FastAPI is not installed."""
        async def _noop() -> None:
            pass
        return _noop
