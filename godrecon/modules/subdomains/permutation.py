"""Subdomain permutation scanner.

Takes a set of known subdomains and generates intelligent permutations, then
resolves them to find additional live subdomains.
"""

from __future__ import annotations

import itertools
import re
from typing import Dict, List, Optional, Set

from godrecon.utils.dns_resolver import AsyncDNSResolver
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_LABEL_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$')


def _is_valid_hostname(hostname: str) -> bool:
    if not hostname or len(hostname) > 253:
        return False
    labels = hostname.rstrip('.').split('.')
    return all(label and _LABEL_RE.match(label) for label in labels)


_PREFIXES = [
    "dev", "staging", "test", "api", "admin", "internal", "prod", "beta",
    "alpha", "pre", "post", "old", "new", "backup", "temp", "tmp", "uat",
    "qa", "demo", "sandbox", "lab", "stg", "preprod", "canary", "preview",
    "app", "web", "portal", "secure", "cdn", "static", "media",
]

_SUFFIXES = [
    "dev", "staging", "test", "api", "admin", "internal", "prod", "beta",
    "v2", "v3", "old", "new", "backup", "2", "3", "4",
]

_SEPARATOR_CHARS = ["-", ".", ""]

_NUMBER_RE = re.compile(r'(\d+)$')


def _generate_number_variants(label: str) -> List[str]:
    """Generate numeric increment/decrement variants of a label.

    Args:
        label: Subdomain label to vary (e.g. ``"server1"``).

    Returns:
        List of variant label strings.
    """
    match = _NUMBER_RE.search(label)
    if not match:
        return []
    base = label[: match.start()]
    n = int(match.group(1))
    return [f"{base}{n + i}" for i in range(1, 4) if n + i != n]


def _generate_permutations(subdomain: str, root_domain: str) -> Set[str]:
    """Generate permutation candidates for a single *subdomain*.

    Args:
        subdomain: Full subdomain string (e.g. ``"api.example.com"``).
        root_domain: Root domain for scope (e.g. ``"example.com"``).

    Returns:
        Set of permutation candidates (fully qualified subdomain strings).
    """
    candidates: Set[str] = set()

    # Extract the label(s) before the root domain
    if not subdomain.endswith(f".{root_domain}"):
        return candidates
    sub_part = subdomain[: -(len(root_domain) + 1)]  # e.g. "api" or "api.v2"
    labels = sub_part.split(".")
    first_label = labels[0]

    for prefix in _PREFIXES:
        for sep in _SEPARATOR_CHARS:
            candidates.add(f"{prefix}{sep}{first_label}.{root_domain}")
            candidates.add(f"{first_label}{sep}{prefix}.{root_domain}")

    for suffix in _SUFFIXES:
        for sep in _SEPARATOR_CHARS:
            candidates.add(f"{first_label}{sep}{suffix}.{root_domain}")

    # Number variants
    for variant in _generate_number_variants(first_label):
        candidates.add(f"{variant}.{root_domain}")

    # Hyphenation variants (e.g. "devapi" → "dev-api")
    for i in range(1, len(first_label)):
        left = first_label[:i]
        right = first_label[i:]
        if len(left) >= 2 and len(right) >= 2:
            candidates.add(f"{left}-{right}.{root_domain}")
            candidates.add(f"{left}.{right}.{root_domain}")

    # Remove the original subdomain itself
    candidates.discard(subdomain)
    return candidates


class PermutationScanner:
    """Generate and resolve subdomain permutations.

    Takes a set of known live subdomains and produces permutation candidates,
    then resolves them concurrently to find additional live subdomains.

    Example::

        async with PermutationScanner() as scanner:
            found = await scanner.run(
                domain="example.com",
                known={"api.example.com", "dev.example.com"},
            )
    """

    def __init__(
        self,
        nameservers: Optional[List[str]] = None,
        timeout: int = 5,
        concurrency: int = 500,
    ) -> None:
        """Initialise the permutation scanner.

        Args:
            nameservers: Custom DNS resolver IPs.
            timeout: DNS query timeout in seconds.
            concurrency: Maximum concurrent DNS queries.
        """
        self._nameservers = nameservers
        self._timeout = timeout
        self._concurrency = concurrency
        self._resolver: Optional[AsyncDNSResolver] = None

    async def __aenter__(self) -> "PermutationScanner":
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
        known: Set[str],
    ) -> Dict[str, List[str]]:
        """Generate permutations from *known* subdomains and resolve them.

        Args:
            domain: Root domain for scoping.
            known: Set of already-discovered live subdomain strings.

        Returns:
            Dict mapping new resolved subdomains to their A record IPs.
        """
        if self._resolver is None:
            self._resolver = AsyncDNSResolver(
                nameservers=self._nameservers,
                timeout=self._timeout,
                concurrency=self._concurrency,
            )
            await self._resolver.__aenter__()

        # Generate all permutation candidates
        all_candidates: Set[str] = set()
        for sub in known:
            all_candidates.update(_generate_permutations(sub, domain))

        # Exclude already-known subdomains
        all_candidates -= known
        if not all_candidates:
            return {}

        candidate_list = sorted(c for c in all_candidates if _is_valid_hostname(c))
        logger.info(
            "Permutation scanner: resolving %d candidates for %s",
            len(candidate_list),
            domain,
        )

        resolved = await self._resolver.bulk_resolve(candidate_list, "A")
        results: Dict[str, List[str]] = {
            subdomain: records
            for subdomain, records in resolved.items()
            if records
        }
        logger.info(
            "Permutation scanner found %d new subdomains for %s",
            len(results),
            domain,
        )
        return results
