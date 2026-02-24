"""ASN (Autonomous System Number) intelligence sub-module for GODRECON.

Uses the free BGPView API to look up ASN details for target IPs,
discover IP ranges owned by the same ASN, and identify hosting providers.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List, Optional

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_BGPVIEW_IP_URL = "https://api.bgpview.io/ip/{ip}"
_BGPVIEW_ASN_URL = "https://api.bgpview.io/asn/{asn}/prefixes"
_RATE_LIMIT_INTERVAL = 1.5  # BGPView free tier is fairly strict


class ASNIntelligence:
    """Look up ASN information and IP prefix ranges via BGPView.

    Results are cached in memory to avoid redundant API calls.

    Example::

        async with AsyncHTTPClient() as http:
            asn_intel = ASNIntelligence(http)
            info = await asn_intel.lookup_ip("1.2.3.4")
    """

    def __init__(self, http_client: AsyncHTTPClient) -> None:
        """Initialise with a shared HTTP client.

        Args:
            http_client: Configured HTTP client instance.
        """
        self._http = http_client
        self._ip_cache: Dict[str, Dict[str, Any]] = {}
        self._asn_cache: Dict[str, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()
        self._last_request = 0.0

    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """Look up ASN information for a single IP address.

        Args:
            ip: IPv4 address to look up.

        Returns:
            Dict with ``asn``, ``asn_name``, ``description``, ``country``,
            and ``prefixes`` list.
        """
        if ip in self._ip_cache:
            return self._ip_cache[ip]

        result = await self._fetch_ip_asn(ip)
        self._ip_cache[ip] = result
        return result

    async def lookup_asn_prefixes(self, asn: str) -> List[str]:
        """Return the list of IP prefixes announced by *asn*.

        Args:
            asn: ASN string such as ``"AS13335"`` or just ``"13335"``.

        Returns:
            List of CIDR prefix strings.
        """
        asn_clean = asn.lstrip("ASas")
        if asn_clean in self._asn_cache:
            return self._asn_cache[asn_clean].get("prefixes", [])

        data = await self._fetch_asn_prefixes(asn_clean)
        self._asn_cache[asn_clean] = data
        return data.get("prefixes", [])

    async def _fetch_ip_asn(self, ip: str) -> Dict[str, Any]:
        """Fetch ASN data for *ip* from BGPView.

        Args:
            ip: Target IP address.

        Returns:
            Parsed ASN data dict.
        """
        await self._rate_limit()
        try:
            url = _BGPVIEW_IP_URL.format(ip=ip)
            resp = await self._http.get(url)
            if resp.get("status") != 200:
                return self._empty_ip(ip)
            data = resp.get("json") or {}
            if data.get("status") != "ok":
                return self._empty_ip(ip)
            return self._parse_ip_response(ip, data.get("data", {}))
        except Exception as exc:  # noqa: BLE001
            logger.debug("BGPView IP lookup failed for %s: %s", ip, exc)
            return self._empty_ip(ip)

    async def _fetch_asn_prefixes(self, asn: str) -> Dict[str, Any]:
        """Fetch prefix list for *asn* from BGPView.

        Args:
            asn: Numeric ASN string.

        Returns:
            Dict with ``asn``, ``name``, and ``prefixes`` list.
        """
        await self._rate_limit()
        try:
            url = _BGPVIEW_ASN_URL.format(asn=asn)
            resp = await self._http.get(url)
            if resp.get("status") != 200:
                return {"asn": asn, "prefixes": []}
            data = resp.get("json") or {}
            if data.get("status") != "ok":
                return {"asn": asn, "prefixes": []}
            return self._parse_asn_prefixes(asn, data.get("data", {}))
        except Exception as exc:  # noqa: BLE001
            logger.debug("BGPView ASN prefix lookup failed for %s: %s", asn, exc)
            return {"asn": asn, "prefixes": []}

    async def _rate_limit(self) -> None:
        """Enforce BGPView rate limiting."""
        import time

        async with self._lock:
            wait = _RATE_LIMIT_INTERVAL - (time.time() - self._last_request)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request = time.time()

    @staticmethod
    def _parse_ip_response(ip: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract ASN information from BGPView IP response.

        Args:
            ip: Queried IP address.
            data: ``data`` sub-dict from BGPView response.

        Returns:
            Normalised ASN dict.
        """
        prefixes = data.get("prefixes", [])
        asn_info: Dict[str, Any] = {}
        if prefixes:
            asn_block = prefixes[0].get("asn", {})
            asn_info = {
                "asn": f"AS{asn_block.get('asn', '')}",
                "asn_name": asn_block.get("name", ""),
                "description": asn_block.get("description", ""),
                "country": asn_block.get("country_code", ""),
                "prefix": prefixes[0].get("prefix", ""),
            }

        rir_alloc = data.get("rir_allocation", {})
        ptr = data.get("ptr_record", "")
        return {
            "ip": ip,
            "asn": asn_info.get("asn"),
            "asn_name": asn_info.get("asn_name"),
            "description": asn_info.get("description"),
            "country": asn_info.get("country") or rir_alloc.get("country_code"),
            "prefix": asn_info.get("prefix"),
            "ptr_record": ptr,
        }

    @staticmethod
    def _parse_asn_prefixes(asn: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract prefix list from BGPView ASN prefixes response.

        Args:
            asn: Numeric ASN string.
            data: ``data`` sub-dict from BGPView response.

        Returns:
            Dict with ``asn`` and ``prefixes`` list.
        """
        ipv4 = [p.get("prefix", "") for p in data.get("ipv4_prefixes", []) if p.get("prefix")]
        return {"asn": f"AS{asn}", "prefixes": ipv4}

    @staticmethod
    def _empty_ip(ip: str) -> Dict[str, Any]:
        """Return empty ASN result for *ip*.

        Args:
            ip: Queried IP address.

        Returns:
            Empty ASN dict.
        """
        return {
            "ip": ip,
            "asn": None,
            "asn_name": None,
            "description": None,
            "country": None,
            "prefix": None,
            "ptr_record": None,
        }
