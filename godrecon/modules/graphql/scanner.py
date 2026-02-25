"""GraphQL endpoint discovery and introspection module for GODRECON."""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_GRAPHQL_PATHS = [
    "/graphql", "/graphiql", "/v1/graphql", "/api/graphql",
    "/query", "/gql", "/graphql/v1", "/api/v1/graphql",
]

_INTROSPECTION_QUERY = '{"query":"{ __schema { types { name fields { name type { name } } } } }"}'

_SENSITIVE_TYPE_NAMES = {
    "user", "admin", "password", "token", "secret", "key",
    "credential", "auth", "session", "private", "internal",
}

_SIMPLE_QUERY = '{"query":"{ __typename }"}'


class GraphQLModule(BaseModule):
    """GraphQL endpoint discovery and introspection."""

    name = "graphql"
    description = "GraphQL endpoint discovery and introspection"
    category = "api"
    version = "1.0.0"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        """Probe target for GraphQL endpoints and test introspection."""
        result = ModuleResult(module_name=self.name, target=target)
        timeout = getattr(getattr(config, "general", None), "timeout", 10) or 10
        base_url = f"https://{target}" if not target.startswith("http") else target

        tasks = [
            self._run_safe(
                f"graphql:{path}",
                self._probe_endpoint(base_url.rstrip("/") + path, timeout),
            )
            for path in _GRAPHQL_PATHS
        ]
        probe_results = await asyncio.gather(*tasks)

        for path, probe in zip(_GRAPHQL_PATHS, probe_results):
            if probe is None:
                continue
            endpoint_url = base_url.rstrip("/") + path
            self._build_findings(result, endpoint_url, probe)

        result.raw = {
            "endpoints_checked": len(_GRAPHQL_PATHS),
            "endpoints_found": sum(1 for p in probe_results if p is not None),
        }

        logger.info(
            "GraphQL scan for %s: %d/%d endpoints found",
            target,
            result.raw["endpoints_found"],
            result.raw["endpoints_checked"],
        )
        return result

    @staticmethod
    async def _probe_endpoint(url: str, timeout: int = 10) -> Optional[Dict[str, Any]]:
        """Probe a single endpoint for GraphQL."""
        try:
            import aiohttp

            headers = {"Content-Type": "application/json", "Accept": "application/json"}

            async with aiohttp.ClientSession() as session:
                # Try simple query first to detect GraphQL
                async with session.post(
                    url,
                    data=_SIMPLE_QUERY,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    ssl=False,
                ) as resp:
                    if resp.status not in (200, 400):
                        return None
                    body = await resp.text()
                    if "__typename" not in body and "errors" not in body and "data" not in body:
                        return None

                # Now try introspection
                async with session.post(
                    url,
                    data=_INTROSPECTION_QUERY,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    ssl=False,
                ) as resp2:
                    if resp2.status != 200:
                        return {"introspection_enabled": False, "status": resp2.status}
                    data = await resp2.json(content_type=None)
                    types = (
                        data.get("data", {})
                        .get("__schema", {})
                        .get("types", [])
                    )
                    type_names = [t.get("name", "") for t in types if t.get("name")]
                    sensitive = [
                        t for t in type_names
                        if any(s in t.lower() for s in _SENSITIVE_TYPE_NAMES)
                    ]
                    return {
                        "introspection_enabled": bool(types),
                        "type_count": len(type_names),
                        "type_names": type_names[:20],
                        "sensitive_types": sensitive,
                        "status": resp2.status,
                    }

        except Exception as exc:
            logger.debug("GraphQL probe error for %s: %s", url, exc)
            return None

    @staticmethod
    def _build_findings(
        result: ModuleResult,
        url: str,
        probe: Dict[str, Any],
    ) -> None:
        """Build findings from a probe result."""
        if probe.get("introspection_enabled"):
            sensitive = probe.get("sensitive_types", [])
            severity = "high" if sensitive else "medium"
            result.findings.append(Finding(
                title=f"GraphQL Introspection Enabled: {url}",
                description=(
                    f"GraphQL introspection is enabled at {url}.\n"
                    f"Types found: {probe.get('type_count', 0)}\n"
                    + (f"Sensitive types: {', '.join(sensitive)}" if sensitive else "")
                ),
                severity=severity,
                data=probe,
                tags=["graphql", "introspection", "api"],
            ))
        else:
            result.findings.append(Finding(
                title=f"GraphQL Endpoint Found: {url}",
                description=f"GraphQL endpoint detected at {url} (introspection disabled).",
                severity="info",
                data=probe,
                tags=["graphql", "api"],
            ))

    @staticmethod
    async def _run_safe(name: str, coro: Any) -> Any:
        """Run a coroutine safely."""
        try:
            return await coro
        except Exception as exc:
            logger.warning("GraphQL sub-check '%s' failed: %s", name, exc)
            return None
