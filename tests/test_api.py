"""Tests for godrecon.api.server."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from godrecon.api.server import create_app  # noqa: E402


@pytest.fixture()
def client() -> TestClient:
    """Return a synchronous test client for the default app."""
    return TestClient(create_app())


def test_health_endpoint(client: TestClient) -> None:
    """GET /api/v1/health should return 200 with status ok."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"


def test_modules_endpoint(client: TestClient) -> None:
    """GET /api/v1/modules should return a list."""
    response = client.get("/api/v1/modules")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_create_scan(client: TestClient) -> None:
    """POST /api/v1/scan should return 202 Accepted."""
    payload = {"target": "example.com"}
    response = client.post("/api/v1/scan", json=payload)
    assert response.status_code == 202
