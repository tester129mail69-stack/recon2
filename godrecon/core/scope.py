"""Target and scope management for GODRECON.

Handles domains, IP addresses, CIDRs, ASNs, and exclude rules.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import List, Optional, Set


class ScopeManager:
    """Manages scan targets and determines whether discovered assets are in scope.

    Supports domains, IPv4/IPv6 addresses, CIDR ranges, and regex-based
    exclusion rules.

    Example::

        scope = ScopeManager()
        scope.add_target("example.com")
        scope.add_exclude(r"\\.staging\\.example\\.com$")
        assert scope.in_scope("api.example.com")
        assert not scope.in_scope("staging.example.com")
    """

    def __init__(self) -> None:
        self._domains: Set[str] = set()
        self._ips: Set[str] = set()
        self._cidrs: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._asns: Set[int] = set()
        self._exclude_patterns: List[re.Pattern[str]] = []
        self._wildcard_domains: Set[str] = set()

    # ------------------------------------------------------------------
    # Target registration
    # ------------------------------------------------------------------

    def add_target(self, target: str) -> None:
        """Add a target to scope.

        Args:
            target: A domain name, IP address, CIDR notation, or ``AS<number>`` string.
        """
        target = target.strip()
        if target.startswith("AS") and target[2:].isdigit():
            self._asns.add(int(target[2:]))
            return

        if target.startswith("*."):
            self._wildcard_domains.add(target[2:])
            return

        try:
            net = ipaddress.ip_network(target, strict=False)
            if net.num_addresses == 1:
                self._ips.add(str(net.network_address))
            else:
                self._cidrs.append(net)
            return
        except ValueError:
            pass

        self._domains.add(target.lower())

    def add_exclude(self, pattern: str) -> None:
        """Add a regex pattern to the exclusion list.

        Args:
            pattern: A regular expression string matched against discovered assets.
        """
        self._exclude_patterns.append(re.compile(pattern, re.IGNORECASE))

    def add_asn(self, asn: int) -> None:
        """Add an Autonomous System Number to scope.

        Args:
            asn: The ASN integer value (e.g. ``15169`` for Google).
        """
        self._asns.add(asn)

    def import_from_file(self, path: str) -> None:
        """Import targets from a newline-separated file.

        Args:
            path: Path to the file containing one target per line.
        """
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"Target file not found: {path}")
        for line in file_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                self.add_target(line)

    # ------------------------------------------------------------------
    # Scope queries
    # ------------------------------------------------------------------

    def in_scope(self, asset: str) -> bool:
        """Return ``True`` if *asset* is within scope and not excluded.

        Args:
            asset: A domain name or IP address string.

        Returns:
            Boolean indicating whether the asset should be processed.
        """
        if self._is_excluded(asset):
            return False

        asset = asset.strip().lower()

        # Check direct IP
        try:
            addr = ipaddress.ip_address(asset)
            if str(addr) in self._ips:
                return True
            return any(addr in cidr for cidr in self._cidrs)
        except ValueError:
            pass

        # Check exact domain match
        if asset in self._domains:
            return True

        # Check wildcard domains
        for domain in self._wildcard_domains:
            if asset == domain or asset.endswith("." + domain):
                return True

        # Check if asset is a subdomain of any in-scope domain
        for domain in self._domains:
            if asset.endswith("." + domain):
                return True

        return False

    def _is_excluded(self, asset: str) -> bool:
        """Return ``True`` if *asset* matches any exclusion pattern."""
        return any(pat.search(asset) for pat in self._exclude_patterns)

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def domains(self) -> Set[str]:
        """Set of in-scope domain names."""
        return frozenset(self._domains)  # type: ignore[return-value]

    @property
    def targets(self) -> List[str]:
        """All registered targets as a flat list of strings."""
        result: List[str] = list(self._domains)
        result.extend(self._ips)
        result.extend(str(c) for c in self._cidrs)
        result.extend(f"AS{asn}" for asn in self._asns)
        result.extend(f"*.{d}" for d in self._wildcard_domains)
        return result

    def __len__(self) -> int:
        return (
            len(self._domains)
            + len(self._ips)
            + len(self._cidrs)
            + len(self._asns)
            + len(self._wildcard_domains)
        )

    def __repr__(self) -> str:
        return f"ScopeManager(targets={len(self)})"

    def get_primary_domain(self) -> Optional[str]:
        """Return the first registered domain target, or ``None``.

        Returns:
            The first domain added to scope, useful as the canonical scan target.
        """
        if self._domains:
            return next(iter(self._domains))
        return None
