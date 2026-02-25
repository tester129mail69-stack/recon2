"""Tests for godrecon.modules.graphql.scanner."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from godrecon.core.config import Config
from godrecon.modules.base import ModuleResult
from godrecon.modules.graphql.scanner import GraphQLModule


def test_instantiation():
    mod = GraphQLModule()
    assert mod.name == "graphql"
    assert mod.category == "api"
    assert mod.version == "1.0.0"


def test_build_findings_introspection_enabled():
    """Should add high-severity finding when sensitive types found."""
    result = ModuleResult(module_name="graphql", target="example.com")
    probe = {
        "introspection_enabled": True,
        "type_count": 5,
        "type_names": ["Query", "User", "Admin", "Post"],
        "sensitive_types": ["User", "Admin"],
        "status": 200,
    }
    GraphQLModule._build_findings(result, "https://example.com/graphql", probe)
    assert len(result.findings) == 1
    assert result.findings[0].severity == "high"


def test_build_findings_introspection_disabled():
    """Should add info finding when endpoint found but introspection disabled."""
    result = ModuleResult(module_name="graphql", target="example.com")
    probe = {"introspection_enabled": False, "status": 400}
    GraphQLModule._build_findings(result, "https://example.com/graphql", probe)
    assert len(result.findings) == 1
    assert result.findings[0].severity == "info"


@pytest.mark.asyncio
async def test_execute_finds_endpoint():
    """Should find GraphQL endpoint and return findings."""
    mod = GraphQLModule()
    mock_probe = {
        "introspection_enabled": True,
        "type_count": 3,
        "type_names": ["Query", "User"],
        "sensitive_types": ["User"],
        "status": 200,
    }
    with patch.object(
        GraphQLModule,
        "_probe_endpoint",
        new=AsyncMock(return_value=mock_probe),
    ):
        result = await mod._execute("example.com", Config())
    assert isinstance(result, ModuleResult)
    assert len(result.findings) > 0


@pytest.mark.asyncio
async def test_execute_no_endpoints():
    """Should return empty findings when no GraphQL endpoints found."""
    mod = GraphQLModule()
    with patch.object(
        GraphQLModule,
        "_probe_endpoint",
        new=AsyncMock(return_value=None),
    ):
        result = await mod._execute("example.com", Config())
    assert isinstance(result, ModuleResult)
    assert result.findings == []
    assert result.raw["endpoints_found"] == 0
