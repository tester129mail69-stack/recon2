"""WHOIS lookup module for GODRECON OSINT.

Uses RDAP (Registration Data Access Protocol) for async WHOIS lookups.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_PRIVACY_KEYWORDS = [
    "whoisguard",
    "privacyprotect",
    "privacy protect",
    "domainsbyproxy",
    "domains by proxy",
    "withheld for privacy",
    "contact privacy",
    "redacted for privacy",
    "data protected",
    "identity protect",
    "perfect privacy",
    "private by design",
]


class WHOISLookup:
    """Async WHOIS lookup for domain intelligence via RDAP."""

    def __init__(self, http: AsyncHTTPClient) -> None:
        """Initialise with an existing HTTP client.

        Args:
            http: Shared async HTTP client instance.
        """
        self._http = http

    async def lookup(self, domain: str) -> Dict[str, Any]:
        """Perform WHOIS/RDAP lookup for *domain*.

        Returns:
            Dict with keys: registrar, creation_date, expiry_date, updated_date,
            nameservers, registrant_email, registrant_org, privacy_protected,
            domain_age_days, suspicious_age.
        """
        result: Dict[str, Any] = {
            "registrar": None,
            "creation_date": None,
            "expiry_date": None,
            "updated_date": None,
            "nameservers": [],
            "registrant_email": None,
            "registrant_org": None,
            "privacy_protected": False,
            "domain_age_days": None,
            "suspicious_age": False,
            "rdap_url": f"https://rdap.org/domain/{domain}",
        }

        try:
            resp = await self._http.get(
                f"https://rdap.org/domain/{domain}",
                headers={"Accept": "application/json"},
            )
            if not resp or resp.get("status") not in (200, 201):
                return result

            import json
            data: Dict[str, Any] = {}
            try:
                data = json.loads(resp.get("body", "{}"))
            except Exception:
                return result

            result = self._parse_rdap(data, result)

        except Exception as exc:  # noqa: BLE001
            logger.debug("RDAP lookup failed for %s: %s", domain, exc)

        return result

    def _parse_rdap(
        self, data: Dict[str, Any], result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Parse RDAP JSON response into the result dict.

        Args:
            data: Parsed RDAP JSON.
            result: Result dict to populate.

        Returns:
            Updated result dict.
        """
        # Nameservers
        nameservers: List[str] = []
        for ns in data.get("nameservers", []):
            ldhName = ns.get("ldhName") or ns.get("unicodeName", "")
            if ldhName:
                nameservers.append(ldhName.lower())
        result["nameservers"] = nameservers

        # Events (dates)
        for event in data.get("events", []):
            action = event.get("eventAction", "")
            date_str = event.get("eventDate", "")
            parsed_date = self._parse_date(date_str)
            if action == "registration":
                result["creation_date"] = date_str
                if parsed_date:
                    age = (datetime.now(timezone.utc) - parsed_date).days
                    result["domain_age_days"] = age
                    result["suspicious_age"] = age < 30
            elif action == "expiration":
                result["expiry_date"] = date_str
            elif action == "last changed":
                result["updated_date"] = date_str

        # Entities (registrar, registrant)
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            vcard = entity.get("vcardArray", [])
            org = self._extract_vcard_field(vcard, "org")
            email = self._extract_vcard_field(vcard, "email")
            if "registrar" in roles:
                result["registrar"] = org or entity.get("handle")
            if "registrant" in roles:
                result["registrant_org"] = org
                result["registrant_email"] = email

        # Privacy protection detection
        all_text = str(data).lower()
        result["privacy_protected"] = any(
            kw in all_text for kw in _PRIVACY_KEYWORDS
        )

        return result

    @staticmethod
    def _extract_vcard_field(vcard: Any, field: str) -> Optional[str]:
        """Extract a field value from a vCard array.

        Args:
            vcard: vcardArray from RDAP.
            field: vCard field name to look for.

        Returns:
            Field value string or None.
        """
        if not isinstance(vcard, list) or len(vcard) < 2:
            return None
        entries = vcard[1] if isinstance(vcard[1], list) else []
        for entry in entries:
            if isinstance(entry, list) and entry and str(entry[0]).lower() == field:
                val = entry[-1] if len(entry) > 1 else None
                if isinstance(val, list):
                    val = val[0] if val else None
                return str(val) if val else None
        return None

    @staticmethod
    def _parse_date(date_str: str) -> Optional[datetime]:
        """Parse an ISO 8601 date string.

        Args:
            date_str: Date string from RDAP.

        Returns:
            Aware datetime or None.
        """
        if not date_str:
            return None
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d"):
            try:
                # Truncate both the date string and the format to a common safe length
                trimmed = date_str[:19]
                trimmed_fmt = fmt[:19]
                dt = datetime.strptime(trimmed, trimmed_fmt)
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None
