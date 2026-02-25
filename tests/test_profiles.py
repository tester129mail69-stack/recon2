"""Tests for godrecon.core.profiles."""

from __future__ import annotations

import pytest

from godrecon.core.config import Config, load_config
from godrecon.core.profiles import (
    PROFILES,
    Profile,
    apply_profile,
    get_profile,
    list_profiles,
)


def test_all_profiles_exist() -> None:
    """Every expected profile key should be present."""
    expected = {"quick", "full", "stealth", "web-app", "infrastructure", "osint"}
    assert expected == set(PROFILES.keys())


def test_profile_has_required_fields() -> None:
    """Each profile should have name, description, and enabled_modules."""
    for name, profile in PROFILES.items():
        assert isinstance(profile, Profile)
        assert profile.name == name
        assert profile.description
        assert isinstance(profile.enabled_modules, list)
        assert len(profile.enabled_modules) > 0


@pytest.mark.parametrize(
    "profile_name, expected_modules",
    [
        ("quick", ["subdomains", "dns", "http_probe", "ports"]),
        ("stealth", ["whois", "wayback", "osint", "github_dork", "dns"]),
        (
            "infrastructure",
            ["dns", "ports", "network", "ssl", "cloud", "takeover"],
        ),
        (
            "osint",
            ["whois", "wayback", "osint", "github_dork", "email_sec"],
        ),
    ],
)
def test_profile_modules(profile_name: str, expected_modules: list[str]) -> None:
    """Each profile should enable exactly the expected modules."""
    profile = get_profile(profile_name)
    assert sorted(profile.enabled_modules) == sorted(expected_modules)


def test_full_profile_contains_all_modules() -> None:
    """The 'full' profile should enable all known modules."""
    full = get_profile("full")
    cfg = load_config()
    all_module_names = set(type(cfg.modules).model_fields.keys())
    assert all_module_names == set(full.enabled_modules)


def test_get_profile_invalid_name_raises() -> None:
    """get_profile() should raise ValueError for unknown profile names."""
    with pytest.raises(ValueError, match="Unknown profile"):
        get_profile("nonexistent_profile")


def test_list_profiles_returns_all() -> None:
    """list_profiles() should return all profiles."""
    result = list_profiles()
    assert len(result) == len(PROFILES)
    names = {p.name for p in result}
    assert names == set(PROFILES.keys())


def test_apply_profile_modifies_config() -> None:
    """apply_profile() should enable only the profile's modules."""
    cfg = load_config()
    apply_profile(cfg, "quick")
    # Only the quick profile modules should be True
    quick_modules = set(get_profile("quick").enabled_modules)
    for field_name in type(cfg.modules).model_fields:
        expected = field_name in quick_modules
        assert getattr(cfg.modules, field_name) == expected, (
            f"Module {field_name!r} expected {expected} after applying 'quick' profile"
        )


def test_apply_profile_returns_config() -> None:
    """apply_profile() should return the modified config object."""
    cfg = load_config()
    result = apply_profile(cfg, "stealth")
    assert result is cfg


def test_apply_profile_invalid_name_raises() -> None:
    """apply_profile() should propagate ValueError for bad profile names."""
    cfg = load_config()
    with pytest.raises(ValueError, match="Unknown profile"):
        apply_profile(cfg, "bad_profile_xyz")
