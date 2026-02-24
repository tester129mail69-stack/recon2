"""Shared pytest fixtures for the GODRECON test suite."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from godrecon.core.config import Config


@pytest.fixture
def sample_config() -> Config:
    """Return a default Config instance with no external dependencies."""
    return Config()


@pytest.fixture
def mock_http_client() -> MagicMock:
    """Return a MagicMock simulating an async HTTP client."""
    client = MagicMock()
    client.get = AsyncMock(return_value=MagicMock(status=200, text=AsyncMock(return_value="")))
    client.post = AsyncMock(return_value=MagicMock(status=200, text=AsyncMock(return_value="")))
    return client


@pytest.fixture
def mock_dns_resolver() -> MagicMock:
    """Return a MagicMock simulating an async DNS resolver."""
    resolver = MagicMock()
    resolver.resolve = AsyncMock(return_value=[])
    return resolver
