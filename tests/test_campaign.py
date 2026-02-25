"""Tests for godrecon.core.campaign."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from godrecon.core.campaign import Campaign, CampaignResult, load_targets_from_file
from godrecon.core.config import Config


def _make_config() -> Config:
    return Config()


# ---------------------------------------------------------------------------
# load_targets_from_file
# ---------------------------------------------------------------------------


def test_load_targets_basic(tmp_path: Path):
    f = tmp_path / "targets.txt"
    f.write_text("example.com\ntest.org\n")
    targets = load_targets_from_file(str(f))
    assert targets == ["example.com", "test.org"]


def test_load_targets_ignores_blank_and_comments(tmp_path: Path):
    f = tmp_path / "targets.txt"
    f.write_text("# This is a comment\nexample.com\n\n# another comment\ntest.org\n")
    targets = load_targets_from_file(str(f))
    assert targets == ["example.com", "test.org"]


def test_load_targets_empty_file(tmp_path: Path):
    f = tmp_path / "empty.txt"
    f.write_text("")
    targets = load_targets_from_file(str(f))
    assert targets == []


def test_load_targets_file_not_found():
    with pytest.raises(FileNotFoundError):
        load_targets_from_file("/nonexistent/targets.txt")


def test_load_targets_strips_whitespace(tmp_path: Path):
    f = tmp_path / "targets.txt"
    f.write_text("  example.com  \n  test.org\n")
    targets = load_targets_from_file(str(f))
    assert targets == ["example.com", "test.org"]


# ---------------------------------------------------------------------------
# Campaign initialisation
# ---------------------------------------------------------------------------


def test_campaign_init():
    cfg = _make_config()
    c = Campaign(name="test-campaign", targets=["a.com", "b.com"], config=cfg)
    assert c.name == "test-campaign"
    assert c.targets == ["a.com", "b.com"]
    assert c.profile is None


def test_campaign_init_with_profile():
    cfg = _make_config()
    c = Campaign(name="test", targets=["a.com"], config=cfg, profile="quick")
    assert c.profile == "quick"


# ---------------------------------------------------------------------------
# CampaignResult dataclass
# ---------------------------------------------------------------------------


def test_campaign_result_defaults():
    cr = CampaignResult(name="x", targets_total=3)
    assert cr.targets_completed == 0
    assert cr.targets_failed == 0
    assert cr.results == {}
    assert cr.finished_at is None
    assert cr.summary == {}


# ---------------------------------------------------------------------------
# Campaign.run — mocked ScanEngine
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_campaign_run_success():
    cfg = _make_config()
    targets = ["a.com", "b.com"]

    mock_result = MagicMock()
    mock_result.module_results = {}

    mock_engine = MagicMock()
    mock_engine.run = AsyncMock(return_value=mock_result)

    events: list[dict] = []

    c = Campaign(name="test", targets=targets, config=cfg)
    c.on_event(events.append)

    with patch("godrecon.core.engine.ScanEngine", return_value=mock_engine):
        result = await c.run(max_concurrent=2)

    assert result.targets_completed == 2
    assert result.targets_failed == 0
    assert set(result.results.keys()) == {"a.com", "b.com"}
    assert result.finished_at is not None

    event_types = [e["event"] for e in events]
    assert "campaign_started" in event_types
    assert "campaign_finished" in event_types
    assert event_types.count("target_started") == 2
    assert event_types.count("target_finished") == 2


@pytest.mark.asyncio
async def test_campaign_run_with_failure():
    cfg = _make_config()

    mock_engine = MagicMock()
    mock_engine.run = AsyncMock(side_effect=RuntimeError("scan failed"))

    c = Campaign(name="test", targets=["fail.com"], config=cfg)

    with patch("godrecon.core.engine.ScanEngine", return_value=mock_engine):
        result = await c.run()

    assert result.targets_failed == 1
    assert result.targets_completed == 0
