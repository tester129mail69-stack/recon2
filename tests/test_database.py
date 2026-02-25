"""Tests for godrecon.core.database."""

from __future__ import annotations

import json
import time

import pytest

from godrecon.core.database import ScanStore


@pytest.fixture
def store(tmp_path):
    """Return a ScanStore backed by a temporary database."""
    db_path = str(tmp_path / "test_scans.db")
    s = ScanStore(db_path=db_path)
    yield s
    s.close()


# ---------------------------------------------------------------------------
# save / get
# ---------------------------------------------------------------------------


def test_save_and_get_scan(store):
    """save_scan then get_scan returns the same record."""
    now = time.time()
    store.save_scan("scan1", "example.com", "completed", '{"a":1}', now, now + 5)
    row = store.get_scan("scan1")
    assert row is not None
    assert row["scan_id"] == "scan1"
    assert row["target"] == "example.com"
    assert row["status"] == "completed"
    assert row["result_json"] == '{"a":1}'
    assert row["started_at"] == pytest.approx(now, abs=0.01)
    assert row["finished_at"] == pytest.approx(now + 5, abs=0.01)


def test_get_scan_returns_none_for_missing(store):
    assert store.get_scan("nonexistent") is None


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


def test_list_scans_empty(store):
    assert store.list_scans() == []


def test_list_scans_ordered_newest_first(store):
    t = time.time()
    store.save_scan("a", "a.com", "completed", "{}", t)
    time.sleep(0.01)
    store.save_scan("b", "b.com", "completed", "{}", t + 1)
    rows = store.list_scans()
    assert len(rows) == 2
    # newest (b) should be first
    assert rows[0]["scan_id"] == "b"
    assert rows[1]["scan_id"] == "a"


def test_list_scans_limit(store):
    t = time.time()
    for i in range(10):
        store.save_scan(f"s{i}", "x.com", "completed", "{}", t + i)
    rows = store.list_scans(limit=3)
    assert len(rows) == 3


# ---------------------------------------------------------------------------
# update
# ---------------------------------------------------------------------------


def test_update_scan_status(store):
    t = time.time()
    store.save_scan("upd1", "x.com", "running", "{}", t)
    store.update_scan_status("upd1", "completed", finished_at=t + 10)
    row = store.get_scan("upd1")
    assert row["status"] == "completed"
    assert row["finished_at"] == pytest.approx(t + 10, abs=0.01)
    assert row["error"] is None


def test_update_scan_status_with_error(store):
    t = time.time()
    store.save_scan("upd2", "y.com", "running", "{}", t)
    store.update_scan_status("upd2", "failed", error="timeout", finished_at=t + 1)
    row = store.get_scan("upd2")
    assert row["status"] == "failed"
    assert row["error"] == "timeout"


# ---------------------------------------------------------------------------
# delete
# ---------------------------------------------------------------------------


def test_delete_scan(store):
    t = time.time()
    store.save_scan("del1", "z.com", "completed", "{}", t)
    assert store.delete_scan("del1") is True
    assert store.get_scan("del1") is None


def test_delete_nonexistent_returns_false(store):
    assert store.delete_scan("ghost") is False


# ---------------------------------------------------------------------------
# replace / upsert
# ---------------------------------------------------------------------------


def test_save_scan_replaces_existing(store):
    t = time.time()
    store.save_scan("dup", "a.com", "running", "{}", t)
    store.save_scan("dup", "a.com", "completed", '{"x":2}', t, t + 3)
    row = store.get_scan("dup")
    assert row["status"] == "completed"
    assert row["result_json"] == '{"x":2}'


# ---------------------------------------------------------------------------
# directory auto-creation
# ---------------------------------------------------------------------------


def test_store_creates_parent_directory(tmp_path):
    nested = tmp_path / "deep" / "nested" / "scans.db"
    s = ScanStore(db_path=str(nested))
    s.save_scan("x", "x.com", "pending", "{}", time.time())
    s.close()
    assert nested.exists()


# ---------------------------------------------------------------------------
# context manager
# ---------------------------------------------------------------------------


def test_context_manager(tmp_path):
    db_path = str(tmp_path / "cm.db")
    with ScanStore(db_path=db_path) as s:
        s.save_scan("cm1", "example.com", "pending", "{}", time.time())
        assert s.get_scan("cm1") is not None


# ---------------------------------------------------------------------------
# environment variable override
# ---------------------------------------------------------------------------


def test_env_var_db_path(tmp_path, monkeypatch):
    env_path = str(tmp_path / "env_scans.db")
    monkeypatch.setenv("GODRECON_DB_PATH", env_path)
    s = ScanStore()
    s.save_scan("env1", "env.com", "completed", "{}", time.time())
    row = s.get_scan("env1")
    s.close()
    assert row is not None
    assert row["target"] == "env.com"
