"""TCP port scanner with service detection and banner grabbing.

This is the main entry point for the ``ports`` GODRECON module.  It
orchestrates concurrent port scanning, optional banner grabbing, and
service fingerprinting, then converts the results into structured
:class:`~godrecon.modules.base.Finding` objects.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult
from godrecon.modules.ports.banner import BannerGrabber
from godrecon.modules.ports.fingerprint import ServiceFingerprinter

_DATA_DIR = Path(__file__).parent.parent.parent / "data"
_PORTS_JSON = _DATA_DIR / "ports.json"
_SERVICES_JSON = _DATA_DIR / "services.json"

# Ports that warrant a higher severity finding when exposed
_HIGH_SEVERITY_PORTS = {21, 23, 3389, 5900, 5901, 5902}  # ftp, telnet, rdp, vnc
_HIGH_SEVERITY_DB_PORTS = {3306, 5432, 27017, 6379, 1433, 1521, 5984, 9200}
_MEDIUM_SEVERITY_PORTS = {8080, 8443, 8888, 9090, 4848, 7001, 7002}

_DEFAULT_CONCURRENCY = 200
_DEFAULT_TIMEOUT = 3.0
_DEFAULT_SCAN_TYPE = "top100"
_DEFAULT_BANNER_GRAB = True
_DEFAULT_SERVICE_DETECTION = True


def _load_ports_json() -> Dict[str, Any]:
    try:
        with _PORTS_JSON.open("r") as fh:
            return json.load(fh)
    except Exception:  # noqa: BLE001
        return {}


class PortScannerModule(BaseModule):
    """TCP port scanner with service detection and banner grabbing.

    Performs concurrent TCP connect scans, optionally grabs service
    banners, and fingerprints detected services.  Findings are tagged
    and severity-rated based on the service type.
    """

    name = "ports"
    description = "TCP port scanner with service detection and banner grabbing"
    author = "GODRECON Team"
    version = "1.0.0"
    category = "ports"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        """Run the port scan against *target*.

        Args:
            target: Hostname or IP address to scan.
            config: Global scan configuration.

        Returns:
            :class:`ModuleResult` containing one :class:`Finding` per open port.
        """
        result = ModuleResult(module_name=self.name, target=target)
        port_cfg = getattr(config, "port_scan", None)

        concurrency: int = getattr(port_cfg, "concurrency", _DEFAULT_CONCURRENCY)
        timeout: float = float(getattr(port_cfg, "timeout", _DEFAULT_TIMEOUT))
        banner_grab: bool = getattr(port_cfg, "banner_grab", _DEFAULT_BANNER_GRAB)
        service_detection: bool = getattr(port_cfg, "service_detection", _DEFAULT_SERVICE_DETECTION)

        ports = self._get_ports(config)
        if not ports:
            result.error = "No ports to scan"
            return result

        self.logger.info("Scanning %d ports on %s (concurrency=%d)", len(ports), target, concurrency)

        open_ports = await self._scan_all(target, ports, concurrency, timeout)

        fingerprinter = ServiceFingerprinter.load_services(str(_SERVICES_JSON))
        banner_grabber = BannerGrabber(timeout=timeout) if banner_grab else None

        findings: List[Finding] = []
        open_port_records: List[Dict[str, Any]] = []

        for port_info in open_ports:
            port: int = port_info["port"]

            banner: Optional[str] = None
            if banner_grabber:
                banner = await banner_grabber.grab(target, port)

            fp: Dict[str, Any] = {}
            if service_detection:
                fp = fingerprinter.fingerprint(port, banner)

            record: Dict[str, Any] = {
                "port": port,
                "state": port_info["state"],
                "latency": port_info["latency"],
                "service": fp.get("service", "unknown"),
                "protocol": fp.get("protocol", "tcp"),
                "description": fp.get("description", ""),
                "banner": fp.get("banner", banner or ""),
                "version": fp.get("version", ""),
                "product": fp.get("product", ""),
                "extra_info": fp.get("extra_info", ""),
            }
            open_port_records.append(record)
            findings.append(self._build_finding(target, port_info, fp if fp else {"service": "unknown"}))

        result.findings = findings
        result.raw = {
            "host": target,
            "open_ports": open_port_records,
            "total_scanned": len(ports),
        }

        self.logger.info(
            "Port scan complete for %s — %d/%d open",
            target,
            len(open_ports),
            len(ports),
        )
        return result

    # ------------------------------------------------------------------
    # Scanning helpers
    # ------------------------------------------------------------------

    async def _scan_port(
        self,
        host: str,
        port: int,
        timeout: float,
        sem: asyncio.Semaphore,
    ) -> Optional[Dict[str, Any]]:
        """Attempt a TCP connect to *host*:*port*.

        Args:
            host: Target host.
            port: TCP port to probe.
            timeout: Connection timeout in seconds.
            sem: Concurrency semaphore.

        Returns:
            Dict with ``port``, ``state``, and ``latency`` if the port is
            open, or ``None`` if it is closed/filtered.
        """
        async with sem:
            start = time.monotonic()
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=timeout,
                )
                latency = round(time.monotonic() - start, 4)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:  # noqa: BLE001
                    pass
                return {"port": port, "state": "open", "latency": latency}
            except ConnectionRefusedError:
                return None
            except asyncio.TimeoutError:
                # Filtered — not definitively closed
                return None
            except OSError:
                return None

    async def _scan_all(
        self,
        host: str,
        ports: List[int],
        concurrency: int,
        timeout: float,
    ) -> List[Dict[str, Any]]:
        """Scan all *ports* concurrently.

        Args:
            host: Target host.
            ports: List of TCP port numbers to scan.
            concurrency: Maximum simultaneous connections.
            timeout: Per-port connection timeout.

        Returns:
            List of open-port dicts (``port``, ``state``, ``latency``).
        """
        sem = asyncio.Semaphore(concurrency)
        tasks = [self._scan_port(host, p, timeout, sem) for p in ports]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]

    # ------------------------------------------------------------------
    # Port list selection
    # ------------------------------------------------------------------

    def _get_ports(self, config: Config) -> List[int]:
        """Return the list of ports to scan according to *config*.

        Args:
            config: Global scan configuration.

        Returns:
            Sorted list of TCP port numbers.
        """
        port_cfg = getattr(config, "port_scan", None)
        scan_type: str = getattr(port_cfg, "scan_type", _DEFAULT_SCAN_TYPE)
        custom_ports: List[int] = list(getattr(port_cfg, "custom_ports", []))

        if scan_type == "custom" and custom_ports:
            return sorted(set(custom_ports))

        if scan_type == "full":
            return list(range(1, 65536))

        ports_data = _load_ports_json()

        if scan_type in ports_data:
            return sorted(set(ports_data[scan_type]))

        # Fallback to top100
        return sorted(set(ports_data.get("top100", [])))

    # ------------------------------------------------------------------
    # Finding builder
    # ------------------------------------------------------------------

    def _build_finding(
        self,
        target: str,
        port_info: Dict[str, Any],
        fingerprint: Dict[str, Any],
    ) -> Finding:
        """Create a :class:`Finding` for a single open port.

        Args:
            target: Scanned host.
            port_info: Dict with at least ``port``, ``state``, ``latency``.
            fingerprint: Service fingerprint dict.

        Returns:
            :class:`Finding` with appropriate title, severity, and tags.
        """
        port: int = port_info["port"]
        service: str = fingerprint.get("service", "unknown")
        product: str = fingerprint.get("product", "")
        version: str = fingerprint.get("version", "")
        banner: str = fingerprint.get("banner", "")
        description: str = fingerprint.get("description", "")

        # Severity classification
        if port in _HIGH_SEVERITY_PORTS or port in _HIGH_SEVERITY_DB_PORTS:
            severity = "high"
        elif port in _MEDIUM_SEVERITY_PORTS:
            severity = "medium"
        else:
            severity = "info"

        service_label = product if product else service
        version_label = f" {version}" if version else ""
        title = f"Open Port {port}/tcp ({service_label}{version_label}): {target}"

        desc_parts = [f"Port {port} is open on {target}."]
        if description:
            desc_parts.append(description)
        if banner:
            short_banner = banner[:200] + ("…" if len(banner) > 200 else "")
            desc_parts.append(f"Banner: {short_banner}")
        desc_parts.append(f"Latency: {port_info.get('latency', 'N/A')}s")

        return Finding(
            title=title,
            description="\n".join(desc_parts),
            severity=severity,
            data={
                "port": port,
                "state": port_info.get("state", "open"),
                "latency": port_info.get("latency"),
                "service": service,
                "product": product,
                "version": version,
                "banner": banner,
            },
            tags=["port", "tcp", "open"],
        )
