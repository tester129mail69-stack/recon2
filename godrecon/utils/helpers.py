"""Utility functions for GODRECON.

Helpers for deduplication, domain/IP validation, string normalisation, and
general-purpose data processing.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable, List, TypeVar

T = TypeVar("T")

# RFC-compliant domain name regex
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,}$"
)


def deduplicate(items: Iterable[T]) -> List[T]:
    """Return a list with duplicates removed while preserving insertion order.

    Args:
        items: Any iterable of hashable items.

    Returns:
        Ordered unique list.
    """
    seen: set = set()
    result: List[T] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def is_valid_domain(domain: str) -> bool:
    """Return ``True`` if *domain* is a syntactically valid domain name.

    Args:
        domain: String to validate.

    Returns:
        Boolean validation result.
    """
    if not domain or len(domain) > 253:
        return False
    return bool(_DOMAIN_RE.match(domain))


def is_valid_ip(address: str) -> bool:
    """Return ``True`` if *address* is a valid IPv4 or IPv6 address.

    Args:
        address: String to validate.

    Returns:
        Boolean validation result.
    """
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def is_valid_cidr(cidr: str) -> bool:
    """Return ``True`` if *cidr* is a valid IPv4 or IPv6 network notation.

    Args:
        cidr: String to validate.

    Returns:
        Boolean validation result.
    """
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def normalise_domain(domain: str) -> str:
    """Return *domain* in lowercase with leading ``www.`` and trailing dot stripped.

    Args:
        domain: Raw domain string.

    Returns:
        Normalised domain string.
    """
    domain = domain.strip().lower().rstrip(".")
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def extract_domain(url: str) -> str:
    """Extract the hostname from a URL or return the input unchanged.

    Args:
        url: A URL string such as ``https://example.com/path``.

    Returns:
        Hostname portion of the URL.
    """
    # Remove scheme
    for scheme in ("https://", "http://", "ftp://"):
        if url.startswith(scheme):
            url = url[len(scheme):]
            break
    # Remove path, query, fragment
    return url.split("/")[0].split("?")[0].split("#")[0].split(":")[0]


def chunk_list(items: List[T], size: int) -> List[List[T]]:
    """Split *items* into consecutive sub-lists of at most *size* elements.

    Args:
        items: The list to chunk.
        size: Maximum chunk size.

    Returns:
        List of sub-lists.
    """
    return [items[i: i + size] for i in range(0, len(items), size)]
