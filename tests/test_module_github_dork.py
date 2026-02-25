"""Tests for godrecon.modules.github_dork.scanner."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from godrecon.core.config import Config
from godrecon.modules.base import ModuleResult
from godrecon.modules.github_dork.scanner import GitHubDorkModule


def test_instantiation():
    mod = GitHubDorkModule()
    assert mod.name == "github_dork"
    assert mod.category == "osint"
    assert mod.version == "1.0.0"


@pytest.mark.asyncio
async def test_execute_no_token():
    """Without a GitHub token, returns skipped result."""
    cfg = Config()
    cfg.api_keys.github = ""
    mod = GitHubDorkModule()
    result = await mod._execute("example.com", cfg)
    assert isinstance(result, ModuleResult)
    assert result.raw.get("skipped") is True
    assert result.findings == []


@pytest.mark.asyncio
async def test_execute_with_token():
    """With a GitHub token, searches and returns findings."""
    cfg = Config()
    cfg.api_keys.github = "fake-token"
    mod = GitHubDorkModule()

    mock_hit = {
        "repo_url": "https://github.com/user/repo",
        "file_path": "config.yaml",
        "name": "config.yaml",
        "query": "password",
    }

    with patch.object(
        GitHubDorkModule,
        "_search_github",
        new=AsyncMock(return_value=[mock_hit]),
    ):
        result = await mod._execute("example.com", cfg)

    assert isinstance(result, ModuleResult)
    assert len(result.findings) > 0
    assert result.raw["total"] > 0


@pytest.mark.asyncio
async def test_execute_empty_results():
    """Returns empty findings when no hits."""
    cfg = Config()
    cfg.api_keys.github = "fake-token"
    mod = GitHubDorkModule()

    with patch.object(
        GitHubDorkModule,
        "_search_github",
        new=AsyncMock(return_value=[]),
    ):
        result = await mod._execute("example.com", cfg)

    assert isinstance(result, ModuleResult)
    assert result.findings == []
    assert result.raw["total"] == 0
