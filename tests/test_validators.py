"""Tests for godrecon.utils.validators."""

from __future__ import annotations

import pytest

from godrecon.utils.validators import validate_port_range, validate_target, validate_url


# ---------------------------------------------------------------------------
# validate_target — valid inputs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("example.com", "example.com"),
        ("  example.com  ", "example.com"),
        ("EXAMPLE.COM", "example.com"),
        ("sub.example.com", "sub.example.com"),
        ("*.example.com", "*.example.com"),
        ("192.168.1.1", "192.168.1.1"),
        ("10.0.0.0/8", "10.0.0.0/8"),
        ("192.168.1.0/24", "192.168.1.0/24"),
        ("2001:db8::1", "2001:db8::1"),
        ("2001:db8::/32", "2001:db8::/32"),
        ("::1", "::1"),
        # CIDR with host bits — normalised to network address
        ("192.168.1.5/24", "192.168.1.0/24"),
    ],
)
def test_validate_target_valid(raw, expected):
    assert validate_target(raw) == expected


# ---------------------------------------------------------------------------
# validate_target — invalid inputs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "not a domain!",
        "has space.com",
        "-starts-with-hyphen.com",
        "double..dot.com",
        "a" * 64 + ".com",  # label too long
        "toolong." + "a" * 250 + ".com",  # total too long
        "just-one-label",
    ],
)
def test_validate_target_invalid(raw):
    with pytest.raises(ValueError):
        validate_target(raw)


# ---------------------------------------------------------------------------
# validate_port_range — valid inputs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("80", [80]),
        ("80,443", [80, 443]),
        ("80,443,8080", [80, 443, 8080]),
        ("8000-8003", [8000, 8001, 8002, 8003]),
        ("80,443,8000-8002", [80, 443, 8000, 8001, 8002]),
        ("1", [1]),
        ("65535", [65535]),
        # Duplicates are de-duplicated and sorted
        ("443,80,443", [80, 443]),
    ],
)
def test_validate_port_range_valid(raw, expected):
    assert validate_port_range(raw) == expected


# ---------------------------------------------------------------------------
# validate_port_range — invalid inputs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "abc",
        "80,abc",
        "0",
        "65536",
        "8080-8070",  # start > end
        "8000-99999",
        "80-",
        "-80",
    ],
)
def test_validate_port_range_invalid(raw):
    with pytest.raises(ValueError):
        validate_port_range(raw)


# ---------------------------------------------------------------------------
# validate_url — valid inputs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "https://example.com",
        "https://example.com/path?q=1#anchor",
        "http://192.168.1.1:8080/api",
        "https://sub.example.com/",
    ],
)
def test_validate_url_valid(url):
    assert validate_url(url) == url


def test_validate_url_strips_whitespace():
    assert validate_url("  https://example.com  ") == "https://example.com"


# ---------------------------------------------------------------------------
# validate_url — invalid inputs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "",
        "ftp://example.com",
        "example.com",
        "//example.com",
        "https://",
    ],
)
def test_validate_url_invalid(url):
    with pytest.raises(ValueError):
        validate_url(url)
