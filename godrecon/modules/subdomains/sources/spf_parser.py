"""SPF/DMARC record parser for subdomain discovery."""

from __future__ import annotations

import re
from typing import Set

from godrecon.utils.dns_resolver import AsyncDNSResolver
from godrecon.modules.subdomains.sources.base import SubdomainSource

# Match include:, redirect=, a:, mx:, ptr: modifiers in SPF
_SPF_INCLUDE_RE = re.compile(
    r'(?:include:|redirect=|a:|mx:|ptr:)([\w\.\-]+)',
    re.IGNORECASE,
)
# Match p= tag in DMARC for rua/ruf mailto addresses
_DMARC_URI_RE = re.compile(r'mailto:([^,!\s]+@([\w\.\-]+))', re.IGNORECASE)


class SPFParserSource(SubdomainSource):
    """Discover related domains by parsing SPF and DMARC DNS records.

    Walks ``include:`` and ``redirect=`` directives in SPF records to find
    additional domains and subdomains referenced by the target.  No API key
    required — purely DNS-based.
    """

    name = "spf_parser"
    description = "SPF/DMARC record include-chain parsing"
    requires_api_key = False

    async def fetch(self, domain: str) -> Set[str]:
        """Parse SPF and DMARC records for *domain* to find subdomains.

        Args:
            domain: Root domain to parse records for.

        Returns:
            Set of discovered subdomain strings.
        """
        results: Set[str] = set()
        try:
            async with AsyncDNSResolver() as resolver:
                await self._parse_spf(domain, domain, resolver, results, depth=0)
                # DMARC
                dmarc_records = await resolver.resolve(f"_dmarc.{domain}", "TXT")
                for txt in dmarc_records:
                    for match in _DMARC_URI_RE.finditer(txt):
                        host = match.group(2).lower()
                        if host.endswith(f".{domain}") or host == domain:
                            results.add(host)
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("SPF parser error: %s", exc)
        return results

    async def _parse_spf(
        self,
        query_domain: str,
        root_domain: str,
        resolver: AsyncDNSResolver,
        results: Set[str],
        depth: int,
    ) -> None:
        """Recursively parse SPF includes for *query_domain*.

        Args:
            query_domain: Domain whose SPF record should be parsed.
            root_domain: Original root domain for scope filtering.
            resolver: Shared DNS resolver instance.
            results: Mutable set to add findings into.
            depth: Current recursion depth (max 5).
        """
        if depth > 5:
            return
        txt_records = await resolver.resolve(query_domain, "TXT")
        for txt in txt_records:
            if "v=spf1" not in txt.lower():
                continue
            for match in _SPF_INCLUDE_RE.finditer(txt):
                included = match.group(1).lower().rstrip(".")
                if included.endswith(f".{root_domain}") or included == root_domain:
                    results.add(included)
                # Recurse into included domains (capped)
                await self._parse_spf(included, root_domain, resolver, results, depth + 1)
