"""Enhanced scope configuration — define and enforce scan boundaries."""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

import yaml


class ScopeConfig:
    """Load and enforce scope boundaries for a scan.

    Supports wildcard domains (``*.example.com``), exact domains, IPv4/IPv6
    addresses, and CIDR ranges for both in-scope and out-of-scope lists.

    Example::

        scope = ScopeConfig()
        scope.add_in_scope("*.example.com")
        scope.add_out_of_scope("production.example.com")
        ok, reason = scope.validate_target("staging.example.com")
    """

    def __init__(self) -> None:
        self._in_scope_domains: list[str] = []
        self._in_scope_wildcards: list[str] = []
        self._in_scope_ips: set[str] = set()
        self._in_scope_cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._out_of_scope_domains: list[str] = []
        self._out_of_scope_wildcards: list[str] = []
        self._out_of_scope_ips: set[str] = set()
        self._out_of_scope_cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_from_file(self, filepath: str) -> None:
        """Load scope definition from a YAML file.

        Expected format::

            scope:
              in_scope:
                - "*.example.com"
                - "10.0.0.0/8"
              out_of_scope:
                - "production.example.com"

        Args:
            filepath: Path to the YAML scope file.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        p = Path(filepath)
        if not p.exists():
            raise FileNotFoundError(f"Scope file not found: {filepath}")
        raw: dict[str, Any] = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        scope_block = raw.get("scope", {})
        for target in scope_block.get("in_scope", []):
            self.add_in_scope(str(target))
        for target in scope_block.get("out_of_scope", []):
            self.add_out_of_scope(str(target))

    # ------------------------------------------------------------------
    # Registration helpers
    # ------------------------------------------------------------------

    def add_in_scope(self, target: str) -> None:
        """Add *target* to the in-scope list.

        Args:
            target: Domain, wildcard domain, IP, or CIDR string.
        """
        _add_to_lists(
            target,
            self._in_scope_domains,
            self._in_scope_wildcards,
            self._in_scope_ips,
            self._in_scope_cidrs,
        )

    def add_out_of_scope(self, target: str) -> None:
        """Add *target* to the out-of-scope exclusion list.

        Args:
            target: Domain, wildcard domain, IP, or CIDR string.
        """
        _add_to_lists(
            target,
            self._out_of_scope_domains,
            self._out_of_scope_wildcards,
            self._out_of_scope_ips,
            self._out_of_scope_cidrs,
        )

    # ------------------------------------------------------------------
    # Scope queries
    # ------------------------------------------------------------------

    def is_in_scope(self, target: str) -> bool:
        """Return ``True`` if *target* is in scope and not excluded.

        Args:
            target: Domain or IP address string.

        Returns:
            Boolean indicating whether the target should be scanned.
        """
        allowed, _ = self.validate_target(target)
        return allowed

    def validate_target(self, target: str) -> tuple[bool, str]:
        """Return *(allowed, reason)* for *target*.

        Args:
            target: Domain or IP address string.

        Returns:
            Tuple of (``bool``, ``str``).  The boolean is ``True`` when the
            target is allowed; the string gives a human-readable reason.
        """
        target = target.strip().lower()

        # If no in-scope rules are defined, everything is in scope by default
        has_in_scope = bool(
            self._in_scope_domains or self._in_scope_wildcards or self._in_scope_ips or self._in_scope_cidrs
        )

        # Check out-of-scope first
        if _matches_lists(
            target,
            self._out_of_scope_domains,
            self._out_of_scope_wildcards,
            self._out_of_scope_ips,
            self._out_of_scope_cidrs,
        ):
            return False, f"{target} is explicitly out of scope"

        if not has_in_scope:
            return True, "no scope restrictions defined"

        if _matches_lists(
            target,
            self._in_scope_domains,
            self._in_scope_wildcards,
            self._in_scope_ips,
            self._in_scope_cidrs,
        ):
            return True, f"{target} is in scope"

        return False, f"{target} is not in the defined scope"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _add_to_lists(
    target: str,
    domains: list[str],
    wildcards: list[str],
    ips: set[str],
    cidrs: list[Any],
) -> None:
    target = target.strip()
    if target.startswith("*."):
        wildcards.append(target[2:].lower())
        return
    try:
        net = ipaddress.ip_network(target, strict=False)
        if net.num_addresses == 1:
            ips.add(str(net.network_address))
        else:
            cidrs.append(net)
        return
    except ValueError:
        pass
    domains.append(target.lower())


def _matches_lists(
    target: str,
    domains: list[str],
    wildcards: list[str],
    ips: set[str],
    cidrs: list[Any],
) -> bool:
    # IP / CIDR matching
    try:
        addr = ipaddress.ip_address(target)
        if str(addr) in ips:
            return True
        return any(addr in cidr for cidr in cidrs)
    except ValueError:
        pass

    # Exact domain match
    if target in domains:
        return True

    # Wildcard domain match: *.example.com matches example.com and sub.example.com
    return any(target == wc or target.endswith("." + wc) for wc in wildcards)
