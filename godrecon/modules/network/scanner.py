"""Network Intelligence Module entry point for GODRECON.

Orchestrates traceroute analysis, CDN/WAF bypass, origin IP discovery,
IP geolocation, ASN intelligence, and network topology mapping.

Auto-discovered by the scan engine via the ``network`` package
``__init__.py`` export.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult
from godrecon.modules.network.asn import ASNIntelligence
from godrecon.modules.network.cdn_bypass import CDNBypassDetector
from godrecon.modules.network.geolocation import IPGeolocation
from godrecon.modules.network.topology import NetworkTopologyMapper
from godrecon.modules.network.traceroute import TracerouteAnalyzer
from godrecon.utils.dns_resolver import AsyncDNSResolver
from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)


class NetworkIntelModule(BaseModule):
    """Network intelligence: traceroute, CDN bypass, origin IP, geolocation, ASN, topology.

    Runs all network sub-modules concurrently and reports findings with
    appropriate severity levels.
    """

    name = "network"
    description = (
        "Network intelligence: traceroute, CDN/WAF bypass, origin IP discovery, "
        "geolocation, ASN lookup, and topology mapping"
    )
    author = "GODRECON Team"
    version = "1.0.0"
    category = "network"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        """Run all network intelligence sub-modules for *target*.

        Args:
            target: Domain or IP address to analyse.
            config: Global scan configuration.

        Returns:
            :class:`ModuleResult` with all network findings.
        """
        result = ModuleResult(module_name=self.name, target=target)
        net_cfg = getattr(config, "network", None)

        enabled_traceroute = getattr(net_cfg, "traceroute", True)
        enabled_cdn_bypass = getattr(net_cfg, "cdn_bypass", True)
        enabled_geolocation = getattr(net_cfg, "geolocation", True)
        enabled_asn = getattr(net_cfg, "asn_lookup", True)
        enabled_topology = getattr(net_cfg, "topology", True)
        max_hops = getattr(net_cfg, "max_traceroute_hops", 30)

        general = config.general
        timeout = general.timeout

        async with AsyncHTTPClient(
            timeout=timeout,
            user_agents=general.user_agents,
            proxy=general.proxy,
            verify_ssl=False,
            retries=1,
            rate_limit=0.0,
        ) as http:
            async with AsyncDNSResolver(
                nameservers=config.dns.resolvers,
                timeout=config.dns.timeout,
            ) as resolver:
                # Run sub-modules concurrently
                (
                    traceroute_result,
                    cdn_result,
                ) = await asyncio.gather(
                    self._run_traceroute(target, max_hops, timeout, enabled_traceroute),
                    self._run_cdn_bypass(http, resolver, target, enabled_cdn_bypass),
                    return_exceptions=False,
                )

                # Collect all IPs for geolocation and ASN enrichment
                all_ips = self._collect_ips(
                    target, traceroute_result, cdn_result
                )

                geo_results, asn_results = await asyncio.gather(
                    self._run_geolocation(http, all_ips, enabled_geolocation),
                    self._run_asn(http, all_ips, enabled_asn),
                )

        # Build topology map
        topology: Optional[Dict[str, Any]] = None
        if enabled_topology:
            mapper = NetworkTopologyMapper()
            topology = mapper.build(
                domain=target,
                cdn_result=cdn_result,
                traceroute_result=traceroute_result,
                geo_results=geo_results,
                asn_results=asn_results,
            )

        # Build findings
        self._add_traceroute_findings(result, traceroute_result, target)
        self._add_cdn_findings(result, cdn_result, target)
        self._add_geo_findings(result, geo_results)
        self._add_asn_findings(result, asn_results)
        if topology:
            self._add_topology_findings(result, topology, target)

        result.raw = {
            "traceroute": traceroute_result,
            "cdn_bypass": cdn_result,
            "geolocation": geo_results,
            "asn": asn_results,
            "topology": topology,
        }
        logger.info(
            "Network intelligence for %s complete — %d findings",
            target,
            len(result.findings),
        )
        return result

    # ------------------------------------------------------------------
    # Sub-module runners
    # ------------------------------------------------------------------

    @staticmethod
    async def _run_traceroute(
        target: str,
        max_hops: int,
        timeout: int,
        enabled: bool,
    ) -> Dict[str, Any]:
        """Run traceroute sub-module.

        Args:
            target: Target host.
            max_hops: Maximum traceroute hops.
            timeout: Per-hop timeout.
            enabled: Whether to run.

        Returns:
            Traceroute result dict.
        """
        if not enabled:
            return {}
        try:
            analyzer = TracerouteAnalyzer(max_hops=max_hops, timeout=timeout)
            return await analyzer.run(target)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Traceroute failed: %s", exc)
            return {}

    @staticmethod
    async def _run_cdn_bypass(
        http: AsyncHTTPClient,
        resolver: AsyncDNSResolver,
        target: str,
        enabled: bool,
    ) -> Dict[str, Any]:
        """Run CDN bypass detection sub-module.

        Args:
            http: Shared HTTP client.
            resolver: Shared DNS resolver.
            target: Target domain.
            enabled: Whether to run.

        Returns:
            CDN bypass result dict.
        """
        if not enabled:
            return {}
        try:
            detector = CDNBypassDetector(http, resolver)
            return await detector.run(target)
        except Exception as exc:  # noqa: BLE001
            logger.warning("CDN bypass detection failed: %s", exc)
            return {}

    @staticmethod
    async def _run_geolocation(
        http: AsyncHTTPClient,
        ips: List[str],
        enabled: bool,
    ) -> Dict[str, Any]:
        """Run IP geolocation for all discovered IPs.

        Args:
            http: Shared HTTP client.
            ips: List of IPv4 addresses.
            enabled: Whether to run.

        Returns:
            Dict mapping IP → geolocation data.
        """
        if not enabled or not ips:
            return {}
        try:
            geo = IPGeolocation(http)
            return await geo.lookup_many(ips)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Geolocation failed: %s", exc)
            return {}

    @staticmethod
    async def _run_asn(
        http: AsyncHTTPClient,
        ips: List[str],
        enabled: bool,
    ) -> Dict[str, Any]:
        """Run ASN intelligence for all discovered IPs.

        Args:
            http: Shared HTTP client.
            ips: List of IPv4 addresses.
            enabled: Whether to run.

        Returns:
            Dict mapping IP → ASN data.
        """
        if not enabled or not ips:
            return {}
        try:
            asn_intel = ASNIntelligence(http)
            tasks = {ip: asyncio.create_task(asn_intel.lookup_ip(ip)) for ip in ips}
            results: Dict[str, Any] = {}
            for ip, task in tasks.items():
                try:
                    results[ip] = await task
                except Exception as exc:  # noqa: BLE001
                    logger.debug("ASN lookup failed for %s: %s", ip, exc)
            return results
        except Exception as exc:  # noqa: BLE001
            logger.warning("ASN intelligence failed: %s", exc)
            return {}

    # ------------------------------------------------------------------
    # IP collection helper
    # ------------------------------------------------------------------

    @staticmethod
    def _collect_ips(
        target: str,
        traceroute_result: Dict[str, Any],
        cdn_result: Dict[str, Any],
    ) -> List[str]:
        """Collect all unique IPs discovered across sub-modules.

        Args:
            target: Primary scan target (may be an IP).
            traceroute_result: Traceroute output.
            cdn_result: CDN bypass output.

        Returns:
            Deduplicated list of IPv4 address strings.
        """
        import re
        ip_pattern = re.compile(r"^\d+\.\d+\.\d+\.\d+$")

        ips: List[str] = []
        # Include target if it is a raw IP
        if ip_pattern.match(target):
            ips.append(target)

        # Origin IPs from CDN bypass
        ips.extend(cdn_result.get("origin_ips", []))
        for v in cdn_result.get("validated_origin_ips", []):
            ip = v.get("ip")
            if ip:
                ips.append(ip)

        # Hop IPs from traceroute
        for hop in traceroute_result.get("hops", []):
            if hop.get("ip"):
                ips.append(hop["ip"])

        return list(dict.fromkeys(ips))  # preserve order, deduplicate

    # ------------------------------------------------------------------
    # Finding builders
    # ------------------------------------------------------------------

    @staticmethod
    def _add_traceroute_findings(
        result: ModuleResult, data: Dict[str, Any], target: str
    ) -> None:
        """Add traceroute findings to *result*.

        Args:
            result: Module result to append to.
            data: Traceroute output dict.
            target: Target domain/IP.
        """
        if not data:
            return
        if not data.get("available", True):
            result.findings.append(
                Finding(
                    title=f"Traceroute Unavailable: {target}",
                    description="The traceroute binary is not available on this system.",
                    severity="info",
                    data=data,
                    tags=["network", "traceroute"],
                )
            )
            return

        hops = data.get("total_hops", 0)
        analysis = data.get("analysis", {})
        bottlenecks = analysis.get("bottlenecks", [])

        result.findings.append(
            Finding(
                title=f"Traceroute to {target}: {hops} hops",
                description=(
                    f"Network path to {target} traverses {hops} responsive hops. "
                    f"Average RTT: {analysis.get('avg_rtt_ms')} ms. "
                    f"Bottlenecks detected: {len(bottlenecks)}."
                ),
                severity="info",
                data=data,
                tags=["network", "traceroute"],
            )
        )
        for bn in bottlenecks:
            result.findings.append(
                Finding(
                    title=f"Network Bottleneck at hop {bn['hop']}: {bn.get('ip')}",
                    description=f"RTT increase of {bn['rtt_increase_ms']} ms at hop {bn['hop']}.",
                    severity="info",
                    data=bn,
                    tags=["network", "traceroute", "bottleneck"],
                )
            )

    @staticmethod
    def _add_cdn_findings(
        result: ModuleResult, data: Dict[str, Any], target: str
    ) -> None:
        """Add CDN/WAF bypass findings to *result*.

        Args:
            result: Module result to append to.
            data: CDN bypass output dict.
            target: Target domain.
        """
        if not data:
            return

        cdn_detected = data.get("cdn_detected", False)
        cdn_provider = data.get("cdn_provider")
        validated = data.get("validated_origin_ips", [])
        raw_origin = data.get("origin_ips", [])

        if not cdn_detected:
            result.findings.append(
                Finding(
                    title=f"No CDN/WAF Detected: {target}",
                    description=(
                        "The target does not appear to be behind a CDN or WAF. "
                        "The origin server is directly exposed to the internet."
                    ),
                    severity="medium",
                    data=data,
                    tags=["network", "cdn", "exposure"],
                )
            )
        else:
            result.findings.append(
                Finding(
                    title=f"CDN/WAF Detected: {cdn_provider} — {target}",
                    description=(
                        f"Target is protected by {cdn_provider}. "
                        f"Evidence: {', '.join(data.get('cdn_evidence', []))}."
                    ),
                    severity="info",
                    data=data,
                    tags=["network", "cdn", cdn_provider or ""],
                )
            )

        # High severity: validated origin IP discovered behind CDN
        if validated and cdn_detected:
            for v in validated:
                result.findings.append(
                    Finding(
                        title=f"Origin IP Discovered Behind CDN: {v['ip']}",
                        description=(
                            f"The real origin IP {v['ip']} was discovered behind {cdn_provider}. "
                            f"Confidence: {v['confidence'] * 100:.0f}%. "
                            "Direct access to the origin IP may bypass CDN/WAF protections."
                        ),
                        severity="high",
                        data=v,
                        tags=["network", "cdn", "origin-ip", "bypass"],
                    )
                )

        # Medium: origin IP on subdomain (not validated against CDN body)
        elif raw_origin and not validated:
            for ip in raw_origin:
                result.findings.append(
                    Finding(
                        title=f"Potential Origin IP Exposed on Subdomain: {ip}",
                        description=(
                            f"IP {ip} was found via origin-revealing subdomain or DNS record. "
                            "This may be the real origin server."
                        ),
                        severity="medium",
                        data={"ip": ip},
                        tags=["network", "cdn", "origin-ip"],
                    )
                )

    @staticmethod
    def _add_geo_findings(
        result: ModuleResult, geo_data: Dict[str, Any]
    ) -> None:
        """Add geolocation info findings.

        Args:
            result: Module result to append to.
            geo_data: Dict mapping IP → geolocation dict.
        """
        if not geo_data:
            return
        for ip, geo in geo_data.items():
            if not geo.get("country"):
                continue
            desc_parts = [
                f"IP: {ip}",
                f"Country: {geo.get('country')}",
            ]
            if geo.get("city"):
                desc_parts.append(f"City: {geo.get('city')}")
            if geo.get("isp"):
                desc_parts.append(f"ISP: {geo.get('isp')}")
            if geo.get("asn"):
                desc_parts.append(f"ASN: {geo.get('asn')}")
            if geo.get("hosting"):
                desc_parts.append(f"Hosting: {geo.get('hosting')}")
            result.findings.append(
                Finding(
                    title=f"IP Geolocation: {ip}",
                    description="\n".join(desc_parts),
                    severity="info",
                    data=geo,
                    tags=["network", "geolocation", ip],
                )
            )

    @staticmethod
    def _add_asn_findings(
        result: ModuleResult, asn_data: Dict[str, Any]
    ) -> None:
        """Add ASN intelligence info findings.

        Args:
            result: Module result to append to.
            asn_data: Dict mapping IP → ASN dict.
        """
        if not asn_data:
            return
        reported_asns: List[str] = []
        for ip, asn in asn_data.items():
            asn_num = asn.get("asn")
            if not asn_num or asn_num in reported_asns:
                continue
            reported_asns.append(asn_num)
            desc_parts = [f"ASN: {asn_num}"]
            if asn.get("asn_name"):
                desc_parts.append(f"Name: {asn.get('asn_name')}")
            if asn.get("description"):
                desc_parts.append(f"Description: {asn.get('description')}")
            if asn.get("country"):
                desc_parts.append(f"Country: {asn.get('country')}")
            if asn.get("prefix"):
                desc_parts.append(f"Announced Prefix: {asn.get('prefix')}")
            result.findings.append(
                Finding(
                    title=f"ASN Intelligence: {asn_num}",
                    description="\n".join(desc_parts),
                    severity="info",
                    data=asn,
                    tags=["network", "asn", asn_num],
                )
            )

    @staticmethod
    def _add_topology_findings(
        result: ModuleResult, topology: Dict[str, Any], target: str
    ) -> None:
        """Add a network topology summary finding.

        Args:
            result: Module result to append to.
            topology: Topology map dict.
            target: Target domain.
        """
        if not topology:
            return
        total = topology.get("total_ips", 0)
        cdn = topology.get("cdn_provider") or "none"
        result.findings.append(
            Finding(
                title=f"Network Topology: {target}",
                description=(
                    f"Network topology mapped for {target}. "
                    f"Total IPs: {total}. CDN layer: {cdn}. "
                    f"Nodes: {len(topology.get('nodes', []))}."
                ),
                severity="info",
                data=topology,
                tags=["network", "topology"],
            )
        )
