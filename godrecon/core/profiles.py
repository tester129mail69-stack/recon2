"""Scan profiles — predefined module configurations for common use cases."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Profile:
    """A named scan profile with a set of enabled modules."""

    name: str
    description: str
    enabled_modules: List[str] = field(default_factory=list)


PROFILES: Dict[str, Profile] = {
    "quick": Profile(
        name="quick",
        description="Fast surface-level reconnaissance",
        enabled_modules=["subdomains", "dns", "http_probe", "ports"],
    ),
    "full": Profile(
        name="full",
        description="Complete reconnaissance with all modules",
        enabled_modules=[
            "subdomains", "dns", "http_probe", "ports", "tech", "osint",
            "takeover", "cloud", "vulns", "crawl", "ssl", "email_sec",
            "screenshots", "api_intel", "content_discovery", "network",
            "visual", "whois", "wayback", "github_dork", "waf", "cors",
            "graphql", "jwt", "favicon",
        ],
    ),
    "stealth": Profile(
        name="stealth",
        description="Passive-only reconnaissance, no active scanning",
        enabled_modules=["whois", "wayback", "osint", "github_dork", "dns"],
    ),
    "web-app": Profile(
        name="web-app",
        description="Web application security assessment",
        enabled_modules=[
            "http_probe", "ssl", "tech", "crawl", "cors", "graphql",
            "jwt", "vulns", "content_discovery", "waf", "favicon",
        ],
    ),
    "infrastructure": Profile(
        name="infrastructure",
        description="Infrastructure and network reconnaissance",
        enabled_modules=["dns", "ports", "network", "ssl", "cloud", "takeover"],
    ),
    "osint": Profile(
        name="osint",
        description="Open-source intelligence gathering",
        enabled_modules=["whois", "wayback", "osint", "github_dork", "email_sec"],
    ),
}


def get_profile(name: str) -> Profile:
    """Return the profile for the given name, or raise ValueError if not found.

    Args:
        name: The profile name (e.g. "quick", "full", "stealth").

    Returns:
        The matching :class:`Profile` instance.

    Raises:
        ValueError: If no profile with that name exists.
    """
    if name not in PROFILES:
        available = ", ".join(sorted(PROFILES.keys()))
        raise ValueError(f"Unknown profile {name!r}. Available profiles: {available}")
    return PROFILES[name]


def list_profiles() -> List[Profile]:
    """Return all available scan profiles.

    Returns:
        List of all :class:`Profile` instances.
    """
    return list(PROFILES.values())


def apply_profile(config: object, profile_name: str) -> object:
    """Apply a scan profile to *config*, enabling only the profile's modules.

    Disables all modules in ``config.modules``, then enables only those listed
    in the profile.  The *config* object is mutated and returned.

    Args:
        config: A :class:`~godrecon.core.config.Config` instance.
        profile_name: The name of the profile to apply.

    Returns:
        The mutated *config* object.
    """
    profile = get_profile(profile_name)
    modules = config.modules  # type: ignore[attr-defined]
    for field_name in type(modules).model_fields:
        setattr(modules, field_name, field_name in profile.enabled_modules)
    return config
