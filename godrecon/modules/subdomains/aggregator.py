"""Subdomain aggregator module — merges results from all enumeration sources."""

from __future__ import annotations

from typing import List

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult
from godrecon.utils.dns_resolver import AsyncDNSResolver
from godrecon.utils.helpers import deduplicate
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)


class SubdomainAggregator(BaseModule):
    """Aggregate subdomains from passive DNS, certificate transparency, and brute-force.

    This is the Phase 1 stub that performs basic DNS-based subdomain discovery.
    Additional sources (crt.sh, VirusTotal, Shodan, etc.) will be added in later phases.
    """

    name = "subdomains"
    description = "Subdomain enumeration and aggregation"
    author = "GODRECON Team"
    version = "0.1.0"
    category = "discovery"

    # Common subdomain prefixes to probe
    _COMMON_SUBS: List[str] = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
        "vpn", "ssh", "admin", "api", "dev", "test", "staging", "app", "mobile",
        "portal", "remote", "blog", "cdn", "static", "media", "assets", "img",
        "m", "shop", "store", "support", "help", "docs", "git", "gitlab", "github",
        "jenkins", "jira", "confluence", "wiki", "monitor", "status", "health",
        "grafana", "prometheus", "kibana", "elastic", "redis", "db", "database",
        "mysql", "postgres", "mongo", "kafka", "rabbit", "queue", "cache",
        "auth", "sso", "oauth", "login", "register", "signup",
    ]

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        """Enumerate subdomains for *target*.

        Args:
            target: Primary domain to enumerate.
            config: Scan configuration.

        Returns:
            :class:`ModuleResult` with discovered subdomains as findings.
        """
        result = ModuleResult(module_name=self.name, target=target)
        discovered: List[str] = []

        # Use configured resolvers from config
        resolvers = config.dns.resolvers
        dns_timeout = config.dns.timeout

        async with AsyncDNSResolver(
            nameservers=resolvers,
            timeout=dns_timeout,
            concurrency=50,
        ) as resolver:
            # Wildcard check
            is_wildcard = await resolver.detect_wildcard(target)
            if is_wildcard:
                logger.info(
                    "Wildcard DNS detected for %s — results may include false positives",
                    target,
                )

            # Brute-force common subdomains
            candidates = [f"{sub}.{target}" for sub in self._COMMON_SUBS]
            resolved = await resolver.bulk_resolve(candidates, "A")

            for subdomain, records in resolved.items():
                if records:
                    discovered.append(subdomain)
                    result.findings.append(
                        Finding(
                            title=f"Subdomain: {subdomain}",
                            description=f"Resolves to: {', '.join(records)}",
                            severity="info",
                            data={"subdomain": subdomain, "ip_addresses": records},
                            tags=["subdomain", "dns"],
                        )
                    )

        discovered = deduplicate(discovered)
        result.raw = {
            "subdomains": discovered,
            "count": len(discovered),
            "wildcard_detected": is_wildcard,
        }
        logger.info(
            "Subdomain aggregator found %d subdomains for %s",
            len(discovered),
            target,
        )
        return result
