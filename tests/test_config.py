"""Tests for godrecon.core.config."""

from __future__ import annotations

import pytest

from godrecon.core.config import (
    Config,
    ContentDiscoveryConfig,
    PortScanConfig,
    VulnsConfig,
    load_config,
)


def test_default_config_instantiates():
    """Config can be created with all defaults."""
    cfg = Config()
    assert cfg.general.threads == 50
    assert cfg.general.timeout == 10
    assert cfg.general.retries == 3


def test_default_dns_resolvers():
    cfg = Config()
    assert "8.8.8.8" in cfg.dns.resolvers
    assert "1.1.1.1" in cfg.dns.resolvers


def test_port_scan_config_defaults():
    psc = PortScanConfig()
    assert psc.scan_type == "top100"
    assert psc.banner_grab is True
    assert psc.concurrency == 500


def test_vulns_config_defaults():
    vc = VulnsConfig()
    assert vc.cve_lookup is True
    assert vc.safe_mode is True
    assert vc.severity_threshold == "info"


def test_content_discovery_config_defaults():
    cdc = ContentDiscoveryConfig()
    assert 200 in cdc.status_codes
    assert cdc.check_sensitive_files is True


def test_load_config_from_yaml_string(tmp_path):
    """load_config reads a YAML file and returns a valid Config."""
    yaml_content = "general:\n  threads: 99\n  timeout: 5\n"
    config_file = tmp_path / "test_config.yaml"
    config_file.write_text(yaml_content)

    cfg = load_config(str(config_file))
    assert cfg.general.threads == 99
    assert cfg.general.timeout == 5


def test_load_config_missing_file_uses_defaults(tmp_path):
    """load_config falls back to defaults when the file does not exist."""
    cfg = load_config(str(tmp_path / "nonexistent.yaml"))
    assert cfg.general.threads == 50


def test_modules_config_defaults():
    cfg = Config()
    assert cfg.modules.subdomains is True
    assert cfg.modules.dns is True
    assert cfg.modules.http_probe is True


def test_api_keys_config_empty_by_default():
    cfg = Config()
    assert cfg.api_keys.shodan == ""
    assert cfg.api_keys.virustotal == ""


def test_env_override(monkeypatch):
    """Environment variables override config values."""
    monkeypatch.setenv("GODRECON__GENERAL__THREADS", "77")
    cfg = load_config("/nonexistent_path_that_does_not_exist.yaml")
    # The env override sets the value as a string; pydantic coerces it to int.
    assert cfg.general.threads == 77
