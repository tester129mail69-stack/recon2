"""Tests for godrecon.core.scope."""

from __future__ import annotations

import pytest

from godrecon.core.scope import ScopeManager


def test_add_domain_and_in_scope():
    sm = ScopeManager()
    sm.add_target("example.com")
    assert sm.in_scope("example.com")
    assert sm.in_scope("api.example.com")
    assert sm.in_scope("sub.api.example.com")


def test_domain_not_in_scope():
    sm = ScopeManager()
    sm.add_target("example.com")
    assert not sm.in_scope("other.com")
    assert not sm.in_scope("evil-example.com")


def test_ipv4_in_scope():
    sm = ScopeManager()
    sm.add_target("192.168.1.1")
    assert sm.in_scope("192.168.1.1")
    assert not sm.in_scope("192.168.1.2")


def test_cidr_in_scope():
    sm = ScopeManager()
    sm.add_target("10.0.0.0/24")
    assert sm.in_scope("10.0.0.1")
    assert sm.in_scope("10.0.0.254")
    assert not sm.in_scope("10.0.1.1")


def test_exclusion_pattern():
    sm = ScopeManager()
    sm.add_target("example.com")
    sm.add_exclude(r"staging\.example\.com$")
    assert not sm.in_scope("staging.example.com")
    assert sm.in_scope("api.example.com")


def test_wildcard_domain():
    sm = ScopeManager()
    sm.add_target("*.example.com")
    assert sm.in_scope("api.example.com")
    assert sm.in_scope("example.com")
    assert not sm.in_scope("other.com")


def test_asn_target():
    sm = ScopeManager()
    sm.add_target("AS15169")
    assert 15169 in sm._asns


def test_targets_property():
    sm = ScopeManager()
    sm.add_target("example.com")
    sm.add_target("10.0.0.1")
    assert "example.com" in sm.targets
    assert "10.0.0.1" in sm.targets


def test_len():
    sm = ScopeManager()
    assert len(sm) == 0
    sm.add_target("example.com")
    assert len(sm) == 1
    sm.add_target("192.168.1.0/24")
    assert len(sm) == 2


def test_get_primary_domain():
    sm = ScopeManager()
    assert sm.get_primary_domain() is None
    sm.add_target("example.com")
    assert sm.get_primary_domain() == "example.com"


def test_import_from_file(tmp_path):
    target_file = tmp_path / "targets.txt"
    target_file.write_text("example.com\n# comment\n192.168.1.1\n")
    sm = ScopeManager()
    sm.import_from_file(str(target_file))
    assert sm.in_scope("example.com")
    assert sm.in_scope("192.168.1.1")


def test_import_from_file_missing():
    sm = ScopeManager()
    with pytest.raises(FileNotFoundError):
        sm.import_from_file("/nonexistent/targets.txt")
