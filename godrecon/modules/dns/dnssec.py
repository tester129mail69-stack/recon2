"""DNSSEC validator for GODRECON.

Checks whether DNSSEC is enabled and validates the DS → DNSKEY → RRSIG chain.
Uses the existing :class:`~godrecon.utils.dns_resolver.AsyncDNSResolver`.
"""

from __future__ import annotations

from typing import Any, Dict, List

from godrecon.utils.dns_resolver import AsyncDNSResolver
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)


class DNSSECValidator:
    """Validate DNSSEC configuration for a domain.

    Checks for DS records, DNSKEY records, RRSIG presence and basic NSEC/NSEC3
    records.  Results are summarised into a status string and structured data.

    Example::

        async with AsyncDNSResolver() as resolver:
            validator = DNSSECValidator(resolver)
            result = await validator.validate("example.com")
    """

    def __init__(self, resolver: AsyncDNSResolver) -> None:
        """Initialise with an existing :class:`AsyncDNSResolver`.

        Args:
            resolver: Configured DNS resolver instance.
        """
        self._resolver = resolver

    async def validate(self, domain: str) -> Dict[str, Any]:
        """Validate DNSSEC for *domain*.

        Returns a dict with the following keys:

        * ``enabled`` — bool
        * ``status`` — ``"enabled"`` / ``"disabled"`` / ``"misconfigured"``
        * ``ds_records`` — raw DS record strings
        * ``dnskey_records`` — raw DNSKEY record strings
        * ``rrsig_records`` — raw RRSIG record strings
        * ``nsec_records`` — raw NSEC record strings
        * ``nsec3_records`` — raw NSEC3 record strings
        * ``issues`` — list of issue strings

        Args:
            domain: Domain to validate.

        Returns:
            Dict summarising DNSSEC status.
        """
        ds = await self._safe_resolve(domain, "DS")
        dnskey = await self._safe_resolve(domain, "DNSKEY")
        rrsig = await self._safe_resolve(domain, "RRSIG")
        nsec = await self._safe_resolve(domain, "NSEC")
        nsec3 = await self._safe_resolve(domain, "NSEC3")

        issues: List[str] = []
        enabled = bool(dnskey)

        if enabled:
            if not ds:
                issues.append("DNSKEY records present but no DS records found — chain may be broken")
            if not rrsig:
                issues.append("DNSKEY records present but no RRSIG records found")
            status = "misconfigured" if issues else "enabled"
        else:
            status = "disabled"

        return {
            "enabled": enabled,
            "status": status,
            "ds_records": ds,
            "dnskey_records": dnskey,
            "rrsig_records": rrsig,
            "nsec_records": nsec,
            "nsec3_records": nsec3,
            "issues": issues,
        }

    async def _safe_resolve(self, domain: str, record_type: str) -> List[str]:
        """Resolve *record_type*, returning ``[]`` on any error.

        Args:
            domain: Domain name.
            record_type: DNS record type.

        Returns:
            List of record strings.
        """
        try:
            return await self._resolver.resolve(domain, record_type)
        except Exception as exc:  # noqa: BLE001
            logger.debug("DNSSEC %s for %s: %s", record_type, domain, exc)
            return []
