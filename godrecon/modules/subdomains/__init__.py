"""Subdomain enumeration module — shared store for inter-module communication."""

from __future__ import annotations

from typing import Dict, List

# Shared store: target -> list of discovered subdomains
# Populated by SubdomainAggregator, consumed by VulnerabilityModule
_SHARED_SUBDOMAIN_STORE: Dict[str, List[str]] = {}


def register_subdomains(target: str, subdomains: List[str]) -> None:
    """Called by SubdomainAggregator after discovery completes."""
    _SHARED_SUBDOMAIN_STORE[target] = list(subdomains)


def get_discovered_subdomains(target: str) -> List[str]:
    """Called by VulnerabilityModule to get all discovered subdomains."""
    return _SHARED_SUBDOMAIN_STORE.get(target, [])
