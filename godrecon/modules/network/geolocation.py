"""IP Geolocation sub-module for GODRECON.

Uses free IP geolocation APIs (ip-api.com, ipinfo.io) with rate limiting
and result caching to resolve country, city, ISP, ASN, and hosting details
for each discovered IP address.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# Free geolocation endpoints – no API key required for low volume
_GEO_APIS = [
    {
        "name": "ip-api",
        "url": "http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,query",
        "parse": "_parse_ipapi",
    },
    {
        "name": "ipinfo",
        "url": "https://ipinfo.io/{ip}/json",
        "parse": "_parse_ipinfo",
    },
]

# Minimum interval between requests to the same API (seconds)
_RATE_LIMIT_INTERVAL = 1.0


class IPGeolocation:
    """Resolve geolocation information for IP addresses.

    Results are cached in memory to avoid duplicate API calls.

    Example::

        async with AsyncHTTPClient() as http:
            geo = IPGeolocation(http)
            info = await geo.lookup("1.2.3.4")
    """

    def __init__(self, http_client: AsyncHTTPClient) -> None:
        """Initialise with a shared HTTP client.

        Args:
            http_client: Configured HTTP client instance.
        """
        self._http = http_client
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._last_request: Dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def lookup(self, ip: str) -> Dict[str, Any]:
        """Look up geolocation information for *ip*.

        Returns cached data if available.

        Args:
            ip: IPv4 address to look up.

        Returns:
            Dict with ``country``, ``city``, ``isp``, ``org``, ``asn``,
            ``hosting`` fields (values may be ``None`` on failure).
        """
        if ip in self._cache:
            return self._cache[ip]

        result = await self._fetch(ip)
        self._cache[ip] = result
        return result

    async def lookup_many(self, ips: List[str]) -> Dict[str, Dict[str, Any]]:
        """Look up geolocation for multiple IPs concurrently.

        Args:
            ips: List of IPv4 addresses.

        Returns:
            Dict mapping each IP to its geolocation dict.
        """
        tasks = [asyncio.create_task(self.lookup(ip)) for ip in ips]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return {
            ip: (res if not isinstance(res, Exception) else self._empty(ip))
            for ip, res in zip(ips, results)
        }

    async def _fetch(self, ip: str) -> Dict[str, Any]:
        """Attempt geolocation from each API in order.

        Args:
            ip: Target IP address.

        Returns:
            Populated geolocation dict, or empty dict on complete failure.
        """
        for api in _GEO_APIS:
            try:
                await self._rate_limit(api["name"])
                url = api["url"].format(ip=ip)
                resp = await self._http.get(url)
                if resp.get("status") == 200:
                    parser = getattr(self, api["parse"])
                    data = parser(resp.get("json") or {})
                    if data.get("country"):
                        return data
            except Exception as exc:  # noqa: BLE001
                logger.debug("Geolocation API %s failed for %s: %s", api["name"], ip, exc)
        return self._empty(ip)

    async def _rate_limit(self, api_name: str) -> None:
        """Enforce per-API rate limiting.

        Args:
            api_name: Name of the API being called.
        """
        import time

        async with self._lock:
            last = self._last_request.get(api_name, 0.0)
            wait = _RATE_LIMIT_INTERVAL - (time.time() - last)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request[api_name] = time.time()

    @staticmethod
    def _parse_ipapi(data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse an ip-api.com JSON response.

        Args:
            data: Parsed JSON dict from ip-api.com.

        Returns:
            Normalised geolocation dict.
        """
        if data.get("status") != "success":
            return {}
        asn_raw = data.get("as", "")
        asn = asn_raw.split(" ")[0] if asn_raw else None
        return {
            "ip": data.get("query"),
            "country": data.get("country"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "asn": asn,
            "hosting": _detect_hosting(data.get("org", "") or data.get("isp", "")),
        }

    @staticmethod
    def _parse_ipinfo(data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse an ipinfo.io JSON response.

        Args:
            data: Parsed JSON dict from ipinfo.io.

        Returns:
            Normalised geolocation dict.
        """
        org = data.get("org", "")
        asn = org.split(" ")[0] if org else None
        return {
            "ip": data.get("ip"),
            "country": data.get("country"),
            "region": data.get("region"),
            "city": data.get("city"),
            "isp": org,
            "org": org,
            "asn": asn,
            "hosting": _detect_hosting(org),
        }

    @staticmethod
    def _empty(ip: str) -> Dict[str, Any]:
        """Return an empty geolocation result for *ip*.

        Args:
            ip: The queried IP address.

        Returns:
            Empty geolocation dict.
        """
        return {
            "ip": ip,
            "country": None,
            "region": None,
            "city": None,
            "isp": None,
            "org": None,
            "asn": None,
            "hosting": None,
        }


# Keywords that identify common hosting / cloud providers
_HOSTING_KEYWORDS: Dict[str, str] = {
    "amazon": "AWS",
    "aws": "AWS",
    "google": "Google Cloud",
    "microsoft": "Azure",
    "azure": "Azure",
    "cloudflare": "Cloudflare",
    "digitalocean": "DigitalOcean",
    "linode": "Linode/Akamai",
    "vultr": "Vultr",
    "hetzner": "Hetzner",
    "ovh": "OVH",
    "fastly": "Fastly",
    "akamai": "Akamai",
}


def _detect_hosting(org_str: str) -> Optional[str]:
    """Detect hosting provider from an organisation string.

    Args:
        org_str: Organisation/ISP string from geolocation API.

    Returns:
        Canonical hosting provider name or ``None``.
    """
    lower = org_str.lower()
    for keyword, provider in _HOSTING_KEYWORDS.items():
        if keyword in lower:
            return provider
    return None
