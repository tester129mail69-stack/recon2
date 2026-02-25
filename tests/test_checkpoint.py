"""Tests for godrecon.core.checkpoint."""

from __future__ import annotations

from pathlib import Path

from godrecon.core.checkpoint import CheckpointManager


def _mgr(tmp_path: Path, scan_id: str = "scan-123") -> CheckpointManager:
    return CheckpointManager(scan_id=scan_id, checkpoint_dir=str(tmp_path / "checkpoints"))


def test_save_creates_file(tmp_path: Path):
    mgr = _mgr(tmp_path)
    mgr.save(completed_modules=["subdomains"], partial_results={"subdomains": []}, target="example.com")
    assert mgr.exists("scan-123")


def test_load_returns_none_when_missing(tmp_path: Path):
    mgr = _mgr(tmp_path)
    assert mgr.load("nonexistent-scan") is None


def test_load_roundtrip(tmp_path: Path):
    mgr = _mgr(tmp_path)
    mgr.save(
        completed_modules=["subdomains", "dns"],
        partial_results={"subdomains": ["a.example.com"]},
        target="example.com",
        config_snapshot={"threads": 10},
    )
    data = mgr.load("scan-123")
    assert data is not None
    assert data["scan_id"] == "scan-123"
    assert data["target"] == "example.com"
    assert "subdomains" in data["completed_modules"]
    assert "dns" in data["completed_modules"]
    assert data["config_snapshot"] == {"threads": 10}
    assert "timestamp" in data


def test_exists_true_after_save(tmp_path: Path):
    mgr = _mgr(tmp_path)
    assert not mgr.exists("scan-123")
    mgr.save([], {})
    assert mgr.exists("scan-123")


def test_delete_removes_file(tmp_path: Path):
    mgr = _mgr(tmp_path)
    mgr.save([], {})
    assert mgr.exists("scan-123")
    mgr.delete("scan-123")
    assert not mgr.exists("scan-123")


def test_delete_nonexistent_is_silent(tmp_path: Path):
    mgr = _mgr(tmp_path)
    mgr.delete("no-such-scan")  # should not raise


def test_list_checkpoints_empty(tmp_path: Path):
    mgr = _mgr(tmp_path)
    assert mgr.list_checkpoints() == []


def test_list_checkpoints_returns_metadata(tmp_path: Path):
    mgr = _mgr(tmp_path, scan_id="s1")
    mgr.save(["mod_a"], {"mod_a": []}, target="t1.com")
    mgr2 = _mgr(tmp_path, scan_id="s2")
    mgr2.save(["mod_b"], {}, target="t2.com")

    # Both managers share the same checkpoint_dir
    checkpoints = mgr.list_checkpoints()
    scan_ids = {c["scan_id"] for c in checkpoints}
    assert "s1" in scan_ids
    assert "s2" in scan_ids


def test_list_checkpoints_metadata_format(tmp_path: Path):
    mgr = _mgr(tmp_path)
    mgr.save(["subdomains"], {"s": []}, target="example.com")
    checkpoints = mgr.list_checkpoints()
    assert len(checkpoints) == 1
    c = checkpoints[0]
    assert c["scan_id"] == "scan-123"
    assert c["target"] == "example.com"
    assert "subdomains" in c["completed_modules"]
    assert isinstance(c["timestamp"], float)


def test_checkpoint_file_format(tmp_path: Path):
    import json

    mgr = _mgr(tmp_path)
    mgr.save(["dns"], {"dns": ["8.8.8.8"]}, target="t.com", config_snapshot={"k": "v"})
    cp_dir = Path(str(tmp_path / "checkpoints"))
    files = list(cp_dir.glob("*.checkpoint.json"))
    assert len(files) == 1
    data = json.loads(files[0].read_text())
    expected_keys = {"scan_id", "target", "completed_modules", "partial_results", "timestamp", "config_snapshot"}
    assert set(data.keys()) >= expected_keys
