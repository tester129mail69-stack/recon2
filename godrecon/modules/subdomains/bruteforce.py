"""DNS brute-force subdomain enumeration module.

Uses the existing :class:`~godrecon.utils.dns_resolver.AsyncDNSResolver` for
high-speed concurrent resolution against a configurable wordlist.
"""

from __future__ import annotations

import asyncio
import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Set

from godrecon.utils.dns_resolver import AsyncDNSResolver
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# Validate label characters (RFC 1123)
_LABEL_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$')

_DEFAULT_WORDLIST_PATHS = [
    Path("wordlists/subdomains-medium.txt"),
    Path("wordlists/subdomains-small.txt"),
    Path("wordlists/subdomains.txt"),
]


def _load_wordlist(wordlist_path: Optional[str] = None) -> List[str]:
    """Load a subdomain wordlist from *wordlist_path* or fall back to built-in defaults.

    Args:
        wordlist_path: Optional explicit path to a wordlist file.

    Returns:
        List of subdomain prefix strings.
    """
    if wordlist_path:
        path = Path(wordlist_path)
        if path.exists():
            return [
                line.strip()
                for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
                if line.strip() and not line.startswith("#")
            ]
        logger.warning("Wordlist not found at %s — falling back to defaults", wordlist_path)

    for default_path in _DEFAULT_WORDLIST_PATHS:
        if default_path.exists():
            return [
                line.strip()
                for line in default_path.read_text(encoding="utf-8", errors="replace").splitlines()
                if line.strip() and not line.startswith("#")
            ]

    # Built-in minimal wordlist as last resort
    return [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
        "vpn", "ssh", "admin", "api", "dev", "test", "staging", "app", "mobile",
        "portal", "remote", "blog", "cdn", "static", "media", "assets", "img",
        "m", "shop", "store", "support", "help", "docs", "git", "gitlab", "github",
        "jenkins", "jira", "confluence", "wiki", "monitor", "status", "health",
        "grafana", "prometheus", "kibana", "elastic", "redis", "db", "database",
        "mysql", "postgres", "mongo", "kafka", "rabbit", "queue", "cache",
        "auth", "sso", "oauth", "login", "register", "signup", "beta", "alpha",
        "prod", "preview", "internal", "corp", "intranet", "extranet", "lab",
        "old", "new", "backup", "v1", "v2", "v3", "secure", "download", "upload",
        "files", "images", "video", "audio", "data", "analytics", "track",
        "api2", "api3", "api-v2", "api-v1", "rest", "graphql", "ws", "socket",
    ]


class BruteForceModule:
    """High-speed DNS brute-force subdomain discovery.

    Uses :class:`~godrecon.utils.dns_resolver.AsyncDNSResolver` to resolve a
    wordlist of subdomain prefixes against the target domain concurrently.

    Example::

        async with BruteForceModule(concurrency=500) as bf:
            found = await bf.run("example.com")
    """

    def __init__(
        self,
        wordlist_path: Optional[str] = None,
        concurrency: int = 500,
        nameservers: Optional[List[str]] = None,
        timeout: int = 5,
    ) -> None:
        """Initialise the brute-force module.

        Args:
            wordlist_path: Path to the wordlist file.
            concurrency: Maximum concurrent DNS queries.
            nameservers: Custom DNS resolver IPs.
            timeout: DNS query timeout in seconds.
        """
        self._wordlist = _load_wordlist(wordlist_path)
        self._concurrency = concurrency
        self._nameservers = nameservers
        self._timeout = timeout
        self._resolver: Optional[AsyncDNSResolver] = None

    async def __aenter__(self) -> "BruteForceModule":
        self._resolver = AsyncDNSResolver(
            nameservers=self._nameservers,
            timeout=self._timeout,
            concurrency=self._concurrency,
        )
        await self._resolver.__aenter__()
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._resolver is not None:
            await self._resolver.__aexit__(None, None, None)

    async def run(
        self,
        domain: str,
        progress_callback: Optional[object] = None,
    ) -> Dict[str, List[str]]:
        """Brute-force subdomains for *domain*.

        Performs wildcard detection first.  If a wildcard is detected, filters
        false positives by comparing A records.

        Args:
            domain: Root domain to brute-force.
            progress_callback: Optional callable invoked with ``(resolved, total)``
                               after each batch completes.

        Returns:
            Dict mapping resolved subdomain to list of IP addresses.
        """
        if self._resolver is None:
            self._resolver = AsyncDNSResolver(
                nameservers=self._nameservers,
                timeout=self._timeout,
                concurrency=self._concurrency,
            )
            await self._resolver.__aenter__()

        # Wildcard detection
        wildcard_ips: Set[str] = set()
        is_wildcard = await self._resolver.detect_wildcard(domain)
        if is_wildcard:
            logger.info(
                "Wildcard detected for %s — will filter false positives", domain
            )
            # Collect wildcard IPs for filtering
            import random
            import string
            for _ in range(3):
                rand = "".join(random.choices(string.ascii_lowercase, k=12))
                records = await self._resolver.resolve(f"{rand}.{domain}", "A")
                wildcard_ips.update(records)

        candidates = [f"{sub}.{domain}" for sub in self._wordlist if _LABEL_RE.match(sub)]
        total = len(candidates)
        results: Dict[str, List[str]] = {}

        start = time.monotonic()
        resolved_count = 0

        # Process in batches for progress reporting
        batch_size = max(100, self._concurrency)
        for i in range(0, len(candidates), batch_size):
            batch = candidates[i: i + batch_size]
            batch_results = await self._resolver.bulk_resolve(batch, "A")
            for subdomain, records in batch_results.items():
                if records:
                    # Filter wildcard false positives
                    real_records = [r for r in records if r not in wildcard_ips]
                    if not is_wildcard or real_records:
                        results[subdomain] = records
            resolved_count += len(batch)
            if progress_callback:
                try:
                    progress_callback(resolved_count, total)
                except Exception:  # noqa: BLE001
                    pass

        elapsed = time.monotonic() - start
        logger.info(
            "Brute-force complete: %d/%d resolved in %.1fs for %s",
            len(results),
            total,
            elapsed,
            domain,
        )
        return results
