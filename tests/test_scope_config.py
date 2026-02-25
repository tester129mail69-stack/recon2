"""Tests for godrecon.core.scope_config."""

from __future__ import annotations

from pathlib import Path

import pytest

from godrecon.core.scope_config import ScopeConfig


def _cfg_with_scope(*in_scope: str, out_of_scope: list[str] | None = None) -> ScopeConfig:
    cfg = ScopeConfig()
    for t in in_scope:
        cfg.add_in_scope(t)
    for t in out_of_scope or []:
        cfg.add_out_of_scope(t)
    return cfg


# ---------------------------------------------------------------------------
# in-scope checks
# ---------------------------------------------------------------------------


def test_exact_domain_in_scope():
    cfg = _cfg_with_scope("example.com")
    assert cfg.is_in_scope("example.com")


def test_subdomain_of_exact_domain_not_matched_by_default():
    """add_in_scope('example.com') does NOT automatically match sub.example.com
    unless wildcard syntax is used."""
    cfg = _cfg_with_scope("example.com")
    # exact match only
    assert cfg.is_in_scope("example.com")
    # sub-domain is NOT in scope because we didn't add a wildcard
    assert not cfg.is_in_scope("sub.example.com")


def test_wildcard_domain_matches_subdomain():
    cfg = _cfg_with_scope("*.example.com")
    assert cfg.is_in_scope("api.example.com")
    assert cfg.is_in_scope("example.com")


def test_wildcard_does_not_match_unrelated():
    cfg = _cfg_with_scope("*.example.com")
    assert not cfg.is_in_scope("evil-example.com")
    assert not cfg.is_in_scope("other.com")


def test_ip_in_scope():
    cfg = _cfg_with_scope("192.168.1.1")
    assert cfg.is_in_scope("192.168.1.1")
    assert not cfg.is_in_scope("192.168.1.2")


def test_cidr_in_scope():
    cfg = _cfg_with_scope("10.0.0.0/24")
    assert cfg.is_in_scope("10.0.0.1")
    assert cfg.is_in_scope("10.0.0.254")
    assert not cfg.is_in_scope("10.0.1.1")


# ---------------------------------------------------------------------------
# out-of-scope checks
# ---------------------------------------------------------------------------


def test_out_of_scope_overrides_in_scope():
    cfg = _cfg_with_scope("*.example.com", out_of_scope=["production.example.com"])
    assert not cfg.is_in_scope("production.example.com")
    assert cfg.is_in_scope("staging.example.com")


def test_out_of_scope_wildcard():
    cfg = _cfg_with_scope("*.example.com", out_of_scope=["*.internal.example.com"])
    assert not cfg.is_in_scope("db.internal.example.com")
    assert cfg.is_in_scope("api.example.com")


def test_cidr_out_of_scope():
    cfg = _cfg_with_scope("10.0.0.0/8", out_of_scope=["10.0.1.0/24"])
    assert not cfg.is_in_scope("10.0.1.50")
    assert cfg.is_in_scope("10.0.0.1")


# ---------------------------------------------------------------------------
# validate_target
# ---------------------------------------------------------------------------


def test_validate_target_in_scope():
    cfg = _cfg_with_scope("example.com")
    ok, reason = cfg.validate_target("example.com")
    assert ok is True
    assert "in scope" in reason


def test_validate_target_out_of_scope():
    cfg = _cfg_with_scope("*.example.com", out_of_scope=["production.example.com"])
    ok, reason = cfg.validate_target("production.example.com")
    assert ok is False
    assert "out of scope" in reason


def test_validate_target_not_in_scope():
    cfg = _cfg_with_scope("example.com")
    ok, reason = cfg.validate_target("other.com")
    assert ok is False


def test_validate_target_no_restrictions():
    """When no in-scope rules are defined, everything should be allowed."""
    cfg = ScopeConfig()
    ok, reason = cfg.validate_target("anything.com")
    assert ok is True


# ---------------------------------------------------------------------------
# YAML loading
# ---------------------------------------------------------------------------


def test_load_from_yaml(tmp_path: Path):
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(
        "scope:\n"
        "  in_scope:\n"
        "    - '*.example.com'\n"
        "    - '10.0.0.0/8'\n"
        "  out_of_scope:\n"
        "    - 'production.example.com'\n"
        "    - '10.0.1.0/24'\n"
    )
    cfg = ScopeConfig()
    cfg.load_from_file(str(scope_file))

    assert cfg.is_in_scope("api.example.com")
    assert not cfg.is_in_scope("production.example.com")
    assert cfg.is_in_scope("10.0.0.5")
    assert not cfg.is_in_scope("10.0.1.10")


def test_load_from_yaml_file_not_found():
    cfg = ScopeConfig()
    with pytest.raises(FileNotFoundError):
        cfg.load_from_file("/nonexistent/scope.yaml")


def test_load_from_yaml_empty_file(tmp_path: Path):
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text("")
    cfg = ScopeConfig()
    cfg.load_from_file(str(scope_file))
    # Empty file means no restrictions — everything in scope
    assert cfg.is_in_scope("anything.com")
