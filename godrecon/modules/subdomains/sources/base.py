"""Base class for all subdomain enumeration sources.

Every source module must inherit from :class:`SubdomainSource` and implement
``async def fetch(self, domain: str) -> Set[str]``.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import Set

from godrecon.utils.logger import get_logger


class SubdomainSource(ABC):
    """Abstract base class for a single subdomain enumeration source.

    Attributes:
        name: Human-readable source identifier (e.g. ``"crt.sh"``).
        description: One-line description of what this source does.
        requires_api_key: Whether a valid API key must be configured.
        api_key_name: Config attribute name on :class:`~godrecon.core.config.APIKeysConfig`.
        rate_limit: Minimum seconds to wait between consecutive requests (0 = no limit).
    """

    name: str = "unknown"
    description: str = ""
    requires_api_key: bool = False
    api_key_name: str = ""
    rate_limit: float = 0.0

    def __init__(self) -> None:
        self.logger = get_logger(f"source.{self.name}")

    @abstractmethod
    async def fetch(self, domain: str) -> Set[str]:
        """Discover subdomains for *domain*.

        Args:
            domain: The root domain to enumerate (e.g. ``"example.com"``).

        Returns:
            Set of discovered subdomain strings.  Must never raise — return an
            empty set on any error.
        """

    async def fetch_safe(self, domain: str, timeout: float = 30.0) -> Set[str]:
        """Wrapper around :meth:`fetch` with a global timeout and error swallow.

        Args:
            domain: Root domain to enumerate.
            timeout: Maximum seconds to wait before giving up.

        Returns:
            Set of subdomains or empty set on error/timeout.
        """
        try:
            return await asyncio.wait_for(self.fetch(domain), timeout=timeout)
        except asyncio.TimeoutError:
            self.logger.debug("Source '%s' timed out for %s", self.name, domain)
            return set()
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("Source '%s' error for %s: %s", self.name, domain, exc)
            return set()

    def __repr__(self) -> str:
        return f"<SubdomainSource {self.name}>"
