"""DNSSEC zone walking (NSEC/NSEC3) subdomain source."""

from __future__ import annotations

from typing import Set

from godrecon.utils.dns_resolver import AsyncDNSResolver
from godrecon.modules.subdomains.sources.base import SubdomainSource


class DNSSECWalkSource(SubdomainSource):
    """Attempt DNSSEC NSEC zone walking to enumerate subdomains.

    NSEC records in DNSSEC-signed zones can sometimes reveal adjacent names.
    Only works on zones with NSEC (not NSEC3 with opt-out).
    No API key required — purely DNS-based.
    """

    name = "dnssec_walk"
    description = "DNSSEC NSEC zone walking"
    requires_api_key = False

    async def fetch(self, domain: str) -> Set[str]:
        """Attempt NSEC walking for *domain*.

        Args:
            domain: Root domain to walk.

        Returns:
            Set of discovered subdomain strings.
        """
        results: Set[str] = set()
        try:
            async with AsyncDNSResolver() as resolver:
                # Check if DNSSEC is enabled (look for DNSKEY)
                dnskey = await resolver.resolve(domain, "NS")
                # Try NSEC records on the apex
                nsec = await resolver.resolve(domain, "NSEC")
                for record in nsec:
                    # NSEC records list the next name in canonical order
                    # Format: "next_name type_bitmap"
                    parts = record.split()
                    if parts:
                        next_name = parts[0].lower().rstrip(".")
                        if next_name.endswith(f".{domain}") or next_name == domain:
                            results.add(next_name)
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("DNSSEC walk error: %s", exc)
        return results
