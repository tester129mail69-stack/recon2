"""Tests for godrecon.utils.helpers."""

from __future__ import annotations

import pytest

from godrecon.utils.helpers import (
    chunk_list,
    deduplicate,
    extract_domain,
    is_valid_cidr,
    is_valid_domain,
    is_valid_ip,
    normalise_domain,
)


# --- deduplicate ---

def test_deduplicate_removes_dupes():
    assert deduplicate([1, 2, 2, 3, 1]) == [1, 2, 3]


def test_deduplicate_preserves_order():
    assert deduplicate(["b", "a", "b", "c"]) == ["b", "a", "c"]


def test_deduplicate_empty():
    assert deduplicate([]) == []


# --- is_valid_domain ---

@pytest.mark.parametrize("domain", [
    "example.com",
    "sub.example.com",
    "api.v2.example.co.uk",
])
def test_valid_domains(domain):
    assert is_valid_domain(domain) is True


@pytest.mark.parametrize("domain", [
    "",
    "localhost",
    "example",
    "-example.com",
    "a" * 254,
    "exam ple.com",
])
def test_invalid_domains(domain):
    assert is_valid_domain(domain) is False


# --- is_valid_ip ---

@pytest.mark.parametrize("addr", ["192.168.1.1", "10.0.0.1", "::1", "2001:db8::1"])
def test_valid_ips(addr):
    assert is_valid_ip(addr) is True


@pytest.mark.parametrize("addr", ["999.0.0.1", "not-an-ip", "", "256.256.256.256"])
def test_invalid_ips(addr):
    assert is_valid_ip(addr) is False


# --- is_valid_cidr ---

@pytest.mark.parametrize("cidr", ["192.168.0.0/24", "10.0.0.0/8", "::1/128"])
def test_valid_cidrs(cidr):
    assert is_valid_cidr(cidr) is True


@pytest.mark.parametrize("cidr", ["192.168.0.0/33", "not-a-cidr", ""])
def test_invalid_cidrs(cidr):
    assert is_valid_cidr(cidr) is False


# --- normalise_domain ---

def test_normalise_strips_www():
    assert normalise_domain("www.example.com") == "example.com"


def test_normalise_lowercases():
    assert normalise_domain("EXAMPLE.COM") == "example.com"


def test_normalise_strips_trailing_dot():
    assert normalise_domain("example.com.") == "example.com"


def test_normalise_strips_whitespace():
    assert normalise_domain("  example.com  ") == "example.com"


# --- extract_domain ---

def test_extract_domain_https():
    assert extract_domain("https://example.com/path?q=1") == "example.com"


def test_extract_domain_http():
    assert extract_domain("http://sub.example.com/page") == "sub.example.com"


def test_extract_domain_no_scheme():
    assert extract_domain("example.com/path") == "example.com"


def test_extract_domain_with_port():
    assert extract_domain("https://example.com:8443/path") == "example.com"


# --- chunk_list ---

def test_chunk_list_basic():
    assert chunk_list([1, 2, 3, 4, 5], 2) == [[1, 2], [3, 4], [5]]


def test_chunk_list_exact_division():
    assert chunk_list([1, 2, 3, 4], 2) == [[1, 2], [3, 4]]


def test_chunk_list_empty():
    assert chunk_list([], 5) == []


def test_chunk_list_larger_than_list():
    assert chunk_list([1, 2], 10) == [[1, 2]]
