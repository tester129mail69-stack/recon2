"""NS delegation walking subdomain source."""

from __future__ import annotations

from typing import Set

from godrecon.utils.dns_resolver import AsyncDNSResolver
from godrecon.modules.subdomains.sources.base import SubdomainSource


class NSDelegationSource(SubdomainSource):
    """Discover subdomains by walking NS delegations.

    Queries NS records for the domain and common subdomains to find
    delegated zones.  No API key required — purely DNS-based.
    """

    name = "ns_delegation"
    description = "NS delegation zone walking"
    requires_api_key = False

    # Common subdomains that often have their own NS delegation
    _DELEGATION_CANDIDATES = [
        "mail", "ftp", "admin", "dev", "test", "staging", "api", "vpn",
        "cdn", "static", "media", "app", "portal", "internal", "corp",
        "intranet", "extranet", "dmz", "lab", "ops", "infra", "data",
        "db", "database", "git", "gitlab", "jenkins", "ci", "prod",
    ]

    async def fetch(self, domain: str) -> Set[str]:
        """Walk NS delegations for *domain* to discover delegated subdomains.

        Args:
            domain: Root domain to walk.

        Returns:
            Set of discovered subdomain strings.
        """
        results: Set[str] = set()
        try:
            async with AsyncDNSResolver() as resolver:
                # Check candidates for NS records (delegated zones)
                candidates = [f"{sub}.{domain}" for sub in self._DELEGATION_CANDIDATES]
                resolved = await resolver.bulk_resolve(candidates, "NS")
                for subdomain, ns_records in resolved.items():
                    if ns_records:
                        results.add(subdomain.lower())
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("NS delegation error: %s", exc)
        return results
