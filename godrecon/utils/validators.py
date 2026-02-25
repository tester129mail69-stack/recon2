"""Input validation utilities for GODRECON.

Provides functions to validate and normalise user-supplied targets, port
ranges, and URLs before they are passed to scan modules.
"""

from __future__ import annotations

import ipaddress
import re
from typing import List
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Domain validation
# ---------------------------------------------------------------------------

# RFC-compliant hostname label regex (no leading/trailing hyphens, max 63 chars)
_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
# Wildcard subdomain prefix allowed (e.g. *.example.com)
_WILDCARD_RE = re.compile(r"^\*\.")


def _is_valid_domain(value: str) -> bool:
    """Return ``True`` if *value* looks like a valid domain name.

    Supports plain hostnames, FQDNs, and wildcard domains (``*.example.com``).

    Args:
        value: String to validate.

    Returns:
        ``True`` when *value* is a valid domain name.
    """
    if _WILDCARD_RE.match(value):
        value = value[2:]

    if len(value) > 253:
        return False

    labels = value.split(".")
    if len(labels) < 2:
        return False

    return all(_LABEL_RE.match(label) for label in labels)


# ---------------------------------------------------------------------------
# Public validators
# ---------------------------------------------------------------------------


def validate_target(target: str) -> str:
    """Validate and normalise a scan target string.

    Accepted forms:

    * Domain name (e.g. ``example.com``, ``*.example.com``)
    * IPv4 address (e.g. ``192.168.1.1``)
    * IPv6 address (e.g. ``::1``)
    * CIDR range (e.g. ``10.0.0.0/8``, ``2001:db8::/32``)

    Args:
        target: Raw target string supplied by the user.

    Returns:
        Normalised target string (whitespace stripped; domain lower-cased).

    Raises:
        ValueError: When *target* is empty or does not match any accepted form.
    """
    stripped = target.strip()
    if not stripped:
        raise ValueError("Target must not be empty.")

    # Try plain IP address first (before CIDR to avoid /32 suffix)
    try:
        addr = ipaddress.ip_address(stripped)
        return str(addr)
    except ValueError:
        pass

    # Try CIDR
    try:
        network = ipaddress.ip_network(stripped, strict=False)
        return str(network)
    except ValueError:
        pass

    # Fall back to domain validation (lower-cased)
    lower = stripped.lower()
    if _is_valid_domain(lower):
        return lower

    raise ValueError(
        f"Invalid target {stripped!r}. "
        "Expected a domain name, IPv4/IPv6 address, or CIDR range."
    )


def validate_port_range(port_str: str) -> List[int]:
    """Parse a port range specification into a sorted list of port numbers.

    Accepts a comma-separated list of individual ports and/or hyphen-delimited
    ranges, e.g. ``"80,443,8000-8080"``.

    Args:
        port_str: Port specification string.

    Returns:
        Sorted list of unique port integers in ``[1, 65535]``.

    Raises:
        ValueError: When the specification is empty, contains non-numeric
            tokens, or includes port numbers outside ``[1, 65535]``.
    """
    stripped = port_str.strip()
    if not stripped:
        raise ValueError("Port range string must not be empty.")

    ports: set[int] = set()
    for token in stripped.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            parts = token.split("-", 1)
            if len(parts) != 2 or not parts[0].isdigit() or not parts[1].isdigit():
                raise ValueError(f"Invalid port range token: {token!r}")
            start, end = int(parts[0]), int(parts[1])
            if not (1 <= start <= 65535) or not (1 <= end <= 65535):
                raise ValueError(
                    f"Port numbers must be between 1 and 65535, got {token!r}."
                )
            if start > end:
                raise ValueError(
                    f"Start port must be ≤ end port in range {token!r}."
                )
            ports.update(range(start, end + 1))
        else:
            if not token.isdigit():
                raise ValueError(f"Invalid port number: {token!r}")
            port = int(token)
            if not (1 <= port <= 65535):
                raise ValueError(
                    f"Port number must be between 1 and 65535, got {port}."
                )
            ports.add(port)

    return sorted(ports)


def validate_url(url: str) -> str:
    """Validate and return a URL string.

    Checks that *url* has an ``http`` or ``https`` scheme and a non-empty
    network location (hostname).

    Args:
        url: URL string to validate.

    Returns:
        The original URL (stripped of surrounding whitespace).

    Raises:
        ValueError: When *url* is malformed, missing a scheme, or missing a host.
    """
    stripped = url.strip()
    if not stripped:
        raise ValueError("URL must not be empty.")

    try:
        parsed = urlparse(stripped)
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"Could not parse URL {stripped!r}: {exc}") from exc

    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"URL scheme must be 'http' or 'https', got {parsed.scheme!r}."
        )
    if not parsed.netloc:
        raise ValueError(f"URL {stripped!r} is missing a host.")

    return stripped
