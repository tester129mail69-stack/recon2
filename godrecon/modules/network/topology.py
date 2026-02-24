"""Network topology mapper sub-module for GODRECON.

Builds a structured network topology map from DNS relationships,
CDN/WAF identification, traceroute hop data, and geolocation information.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from godrecon.utils.logger import get_logger

logger = get_logger(__name__)


class NetworkTopologyMapper:
    """Assemble a topology map from all collected network data.

    Example::

        mapper = NetworkTopologyMapper()
        topology = mapper.build(
            domain="example.com",
            dns_records={"A": ["1.2.3.4"]},
            cdn_result={"cdn_provider": "cloudflare", ...},
            traceroute_result={"hops": [...]},
            geo_results={"1.2.3.4": {...}},
            asn_results={"1.2.3.4": {...}},
        )
    """

    def build(
        self,
        domain: str,
        dns_records: Optional[Dict[str, Any]] = None,
        cdn_result: Optional[Dict[str, Any]] = None,
        traceroute_result: Optional[Dict[str, Any]] = None,
        geo_results: Optional[Dict[str, Dict[str, Any]]] = None,
        asn_results: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Build and return the network topology map.

        Args:
            domain: Primary scan target domain.
            dns_records: Resolved DNS records (type → list of values).
            cdn_result: Output of CDN bypass detection.
            traceroute_result: Output of traceroute analysis.
            geo_results: Per-IP geolocation data.
            asn_results: Per-IP ASN data.

        Returns:
            Structured topology dict with layers, nodes, and edges.
        """
        dns_records = dns_records or {}
        cdn_result = cdn_result or {}
        traceroute_result = traceroute_result or {}
        geo_results = geo_results or {}
        asn_results = asn_results or {}

        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []

        # Root node — the target domain
        nodes.append({"id": domain, "type": "domain", "label": domain})

        # CDN / WAF layer
        cdn_provider = cdn_result.get("cdn_provider")
        cdn_layer: Optional[str] = None
        if cdn_result.get("cdn_detected") and cdn_provider:
            cdn_layer = f"cdn:{cdn_provider}"
            nodes.append({"id": cdn_layer, "type": "cdn", "label": cdn_provider})
            edges.append({"from": domain, "to": cdn_layer, "label": "fronted_by"})

        # Origin IPs
        validated = cdn_result.get("validated_origin_ips", [])
        raw_origin = cdn_result.get("origin_ips", [])
        origin_ips = [v["ip"] for v in validated] if validated else raw_origin

        for ip in origin_ips:
            node = self._build_ip_node(ip, geo_results, asn_results, "origin")
            nodes.append(node)
            src = cdn_layer or domain
            edges.append({"from": src, "to": ip, "label": "origin"})

        # A record IPs (direct targets, may overlap with origin)
        a_records: List[str] = dns_records.get("A", [])
        for ip in a_records:
            if ip not in origin_ips:
                node = self._build_ip_node(ip, geo_results, asn_results, "a_record")
                nodes.append(node)
                edges.append({"from": domain, "to": ip, "label": "resolves_to"})

        # Mail server nodes
        mx_records: List[str] = dns_records.get("MX", [])
        for mx in mx_records:
            mx_host = str(mx).split()[-1].rstrip(".")
            nodes.append({"id": mx_host, "type": "mail_server", "label": mx_host})
            edges.append({"from": domain, "to": mx_host, "label": "mail"})

        # Name server nodes
        ns_records: List[str] = dns_records.get("NS", [])
        for ns in ns_records:
            ns_host = str(ns).rstrip(".")
            nodes.append({"id": ns_host, "type": "nameserver", "label": ns_host})
            edges.append({"from": domain, "to": ns_host, "label": "nameserver"})

        # Traceroute path
        hops = traceroute_result.get("hops", [])
        self._add_traceroute_edges(domain, hops, nodes, edges, geo_results, asn_results)

        # Build layers summary
        layers = self._summarize_layers(
            domain, cdn_provider, origin_ips, a_records, hops
        )

        return {
            "domain": domain,
            "layers": layers,
            "nodes": self._deduplicate_nodes(nodes),
            "edges": edges,
            "cdn_detected": cdn_result.get("cdn_detected", False),
            "cdn_provider": cdn_provider,
            "total_ips": len(set(a_records + origin_ips)),
        }

    @staticmethod
    def _build_ip_node(
        ip: str,
        geo: Dict[str, Dict[str, Any]],
        asn: Dict[str, Dict[str, Any]],
        node_type: str,
    ) -> Dict[str, Any]:
        """Build a node dict for an IP address.

        Args:
            ip: IPv4 address.
            geo: Geolocation results keyed by IP.
            asn: ASN results keyed by IP.
            node_type: Node type label (e.g. ``"origin"``).

        Returns:
            Node dict with enriched metadata.
        """
        geo_data = geo.get(ip, {})
        asn_data = asn.get(ip, {})
        return {
            "id": ip,
            "type": node_type,
            "label": ip,
            "country": geo_data.get("country"),
            "city": geo_data.get("city"),
            "isp": geo_data.get("isp"),
            "asn": asn_data.get("asn") or geo_data.get("asn"),
            "hosting": geo_data.get("hosting"),
        }

    @staticmethod
    def _add_traceroute_edges(
        domain: str,
        hops: List[Dict[str, Any]],
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
        geo: Dict[str, Dict[str, Any]],
        asn: Dict[str, Dict[str, Any]],
    ) -> None:
        """Add traceroute hop nodes and edges to the topology.

        Args:
            domain: The origin domain node ID.
            hops: List of hop dicts from :class:`TracerouteAnalyzer`.
            nodes: Mutable node list to append to.
            edges: Mutable edge list to append to.
            geo: Geolocation results keyed by IP.
            asn: ASN results keyed by IP.
        """
        prev_id = "client"
        nodes.append({"id": "client", "type": "client", "label": "scan_origin"})
        for hop in hops:
            if not hop.get("ip"):
                continue
            ip = hop["ip"]
            geo_data = geo.get(ip, {})
            asn_data = asn.get(ip, {})
            nodes.append({
                "id": ip,
                "type": "hop",
                "label": ip,
                "hop_num": hop["hop"],
                "rtt_ms": hop.get("rtt_ms"),
                "country": geo_data.get("country"),
                "asn": asn_data.get("asn") or geo_data.get("asn"),
            })
            edges.append({
                "from": prev_id,
                "to": ip,
                "label": f"hop_{hop['hop']}",
                "rtt_ms": hop.get("rtt_ms"),
            })
            prev_id = ip

    @staticmethod
    def _summarize_layers(
        domain: str,
        cdn_provider: Optional[str],
        origin_ips: List[str],
        a_records: List[str],
        hops: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Produce a human-readable summary of the network layers.

        Args:
            domain: Target domain.
            cdn_provider: Detected CDN provider (or ``None``).
            origin_ips: Discovered origin IPs.
            a_records: DNS A record IPs.
            hops: Traceroute hops.

        Returns:
            Layers summary dict.
        """
        return {
            "client": "scan origin",
            "network_path": f"{len(hops)} hops" if hops else "unavailable",
            "cdn_layer": cdn_provider or "none detected",
            "dns_layer": {"domain": domain, "a_records": a_records},
            "origin_layer": origin_ips if origin_ips else a_records,
        }

    @staticmethod
    def _deduplicate_nodes(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Return nodes deduplicated by ``id``, preferring later entries.

        Args:
            nodes: Raw list of node dicts (may contain duplicates).

        Returns:
            Deduplicated list.
        """
        seen: Dict[str, Dict[str, Any]] = {}
        for node in nodes:
            seen[node["id"]] = node
        return list(seen.values())
