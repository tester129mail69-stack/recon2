"""API endpoint discovery for GODRECON."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_API_PATHS: List[Dict[str, str]] = [
    {"path": "/api", "description": "Generic API root"},
    {"path": "/api/v1", "description": "API v1"},
    {"path": "/api/v2", "description": "API v2"},
    {"path": "/api/v3", "description": "API v3"},
    {"path": "/swagger", "description": "Swagger UI"},
    {"path": "/swagger.json", "description": "Swagger JSON spec"},
    {"path": "/swagger-ui.html", "description": "Swagger UI HTML"},
    {"path": "/swagger/v1/swagger.json", "description": "Swagger v1 JSON"},
    {"path": "/openapi.json", "description": "OpenAPI JSON spec"},
    {"path": "/openapi.yaml", "description": "OpenAPI YAML spec"},
    {"path": "/api-docs", "description": "API documentation"},
    {"path": "/graphql", "description": "GraphQL endpoint"},
    {"path": "/graphiql", "description": "GraphiQL explorer"},
    {"path": "/v1", "description": "API version 1 root"},
    {"path": "/v2", "description": "API version 2 root"},
    {"path": "/v3", "description": "API version 3 root"},
    {"path": "/rest", "description": "REST API root"},
    {"path": "/ws", "description": "WebSocket endpoint"},
    {"path": "/websocket", "description": "WebSocket endpoint"},
    {"path": "/api/swagger", "description": "API Swagger"},
    {"path": "/.well-known/openapi", "description": "Well-known OpenAPI spec"},
    {"path": "/redoc", "description": "ReDoc API documentation"},
    {"path": "/api/health", "description": "API health check"},
    {"path": "/health", "description": "Service health check"},
    {"path": "/status", "description": "Service status endpoint"},
    {"path": "/metrics", "description": "Prometheus/metrics endpoint"},
]

_GRAPHQL_INTROSPECTION = '{"query":"{ __schema { types { name } } }"}'


class APIDiscovery:
    """Discover API endpoints on target."""

    def __init__(self) -> None:
        """Initialise the API discovery module."""

    async def discover(
        self, target: str, http: AsyncHTTPClient
    ) -> List[Dict[str, Any]]:
        """Discover API endpoints on *target*.

        Args:
            target: Base domain (e.g., ``example.com``).
            http: Shared async HTTP client.

        Returns:
            List of dicts with: url, type, status, description.
        """
        base = f"https://{target}" if not target.startswith("http") else target
        results: List[Dict[str, Any]] = []

        tasks = [
            asyncio.create_task(self._check_path(http, base, entry))
            for entry in _API_PATHS
        ]
        raw = await asyncio.gather(*tasks, return_exceptions=True)

        for item in raw:
            if isinstance(item, dict) and item.get("found"):
                results.append(item)

        # GraphQL introspection check
        graphql_url = f"{base}/graphql"
        graphql_result = await self._check_graphql(http, graphql_url)
        if graphql_result:
            results.append(graphql_result)

        return results

    async def _check_path(
        self, http: AsyncHTTPClient, base: str, entry: Dict[str, str]
    ) -> Dict[str, Any]:
        """Check a single API path for availability.

        Args:
            http: HTTP client.
            base: Base URL.
            entry: Path entry with path and description.

        Returns:
            Dict with url, type, status, description, found flag.
        """
        url = base.rstrip("/") + entry["path"]
        try:
            resp = await http.get(url, allow_redirects=True)
            status = resp.get("status", 0) if resp else 0
            found = status in (200, 201, 301, 302, 307, 401, 403)
            api_type = self._classify_path(entry["path"])
            return {
                "url": url,
                "type": api_type,
                "status": status,
                "description": entry["description"],
                "found": found,
            }
        except Exception as exc:  # noqa: BLE001
            logger.debug("API path check failed %s: %s", url, exc)
            return {"url": url, "found": False, "status": 0, "description": entry["description"]}

    async def _check_graphql(
        self, http: AsyncHTTPClient, graphql_url: str
    ) -> Dict[str, Any]:
        """Check for GraphQL by sending an introspection query.

        Args:
            http: HTTP client.
            graphql_url: URL to probe.

        Returns:
            Finding dict if GraphQL is confirmed, else empty dict.
        """
        try:
            resp = await http.post(
                graphql_url,
                data=_GRAPHQL_INTROSPECTION,
                headers={"Content-Type": "application/json"},
            )
            if not resp:
                return {}
            status = resp.get("status", 0)
            body = resp.get("body", "")
            if status == 200 and "__schema" in body:
                return {
                    "url": graphql_url,
                    "type": "graphql",
                    "status": status,
                    "description": "GraphQL endpoint confirmed via introspection query",
                    "found": True,
                    "introspection_enabled": True,
                }
        except Exception as exc:  # noqa: BLE001
            logger.debug("GraphQL check failed: %s", exc)
        return {}

    @staticmethod
    def _classify_path(path: str) -> str:
        """Classify an API path into a type label.

        Args:
            path: URL path string.

        Returns:
            Type label string.
        """
        path_lower = path.lower()
        if "swagger" in path_lower or "openapi" in path_lower or "api-docs" in path_lower or "redoc" in path_lower:
            return "documentation"
        if "graphql" in path_lower or "graphiql" in path_lower:
            return "graphql"
        if "websocket" in path_lower or path_lower in ("/ws",):
            return "websocket"
        if "health" in path_lower or "status" in path_lower or "metrics" in path_lower:
            return "monitoring"
        return "rest"
