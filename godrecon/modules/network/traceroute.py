"""Traceroute analysis sub-module for GODRECON.

Runs an OS-level traceroute command via ``asyncio.create_subprocess_exec``
and parses the output into structured hop data.
"""

from __future__ import annotations

import asyncio
import platform
import re
from typing import Any, Dict, List, Optional

from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# Regex for a single traceroute hop line
# Handles both "*  *  *" (no response) and "N  hostname (ip)  X ms" patterns
_HOP_RE = re.compile(
    r"^\s*(\d+)\s+"
    r"(?:"
    r"(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)|"  # hostname (ip)
    r"(\d+\.\d+\.\d+\.\d+)"               # bare IP
    r")?"
    r"(?:\s+([\d.]+)\s*ms)?"
)

# Tracert (Windows) hop pattern: "  1    <1 ms    <1 ms    <1 ms  8.8.8.8"
_TRACERT_RE = re.compile(
    r"^\s*(\d+)\s+"
    r"(?:<?\d+\s*ms\s+){1,3}"
    r"(\S+)"
)


class TracerouteAnalyzer:
    """Async traceroute using the system traceroute/tracert binary.

    Runs traceroute via ``asyncio.create_subprocess_exec`` (no raw sockets
    required) and parses hop data.

    Example::

        analyzer = TracerouteAnalyzer(max_hops=20, timeout=5)
        result = await analyzer.run("example.com")
    """

    def __init__(self, max_hops: int = 30, timeout: int = 5) -> None:
        """Initialise the analyser.

        Args:
            max_hops: Maximum number of hops.
            timeout: Per-hop timeout in seconds.
        """
        self.max_hops = max_hops
        self.timeout = timeout
        self._is_windows = platform.system().lower() == "windows"

    async def run(self, target: str) -> Dict[str, Any]:
        """Run traceroute to *target* and return structured hop data.

        Args:
            target: Hostname or IP address to trace.

        Returns:
            Dict with ``hops`` list, ``total_hops``, ``target``, and
            ``available`` flag.
        """
        cmd = self._build_command(target)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self.max_hops * self.timeout + 10,
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                logger.warning("Traceroute to %s timed out", target)
                return self._empty_result(target)
        except FileNotFoundError:
            logger.info("traceroute binary not available on this system")
            return {**self._empty_result(target), "available": False}
        except Exception as exc:  # noqa: BLE001
            logger.warning("Traceroute failed: %s", exc)
            return self._empty_result(target)

        output = stdout.decode(errors="replace")
        hops = self._parse_output(output)
        analysis = self._analyze_hops(hops)
        return {
            "available": True,
            "target": target,
            "hops": hops,
            "total_hops": len([h for h in hops if h.get("ip")]),
            "analysis": analysis,
        }

    def _build_command(self, target: str) -> List[str]:
        """Build the traceroute command list.

        Args:
            target: Destination host.

        Returns:
            Command list suitable for ``asyncio.create_subprocess_exec``.
        """
        if self._is_windows:
            return ["tracert", "-d", "-h", str(self.max_hops), target]
        return [
            "traceroute",
            "-n",
            "-m", str(self.max_hops),
            "-w", str(self.timeout),
            target,
        ]

    def _parse_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse traceroute/tracert output into hop dicts.

        Args:
            output: Raw text output from the traceroute process.

        Returns:
            List of hop dicts with ``hop``, ``ip``, ``hostname``, and ``rtt_ms`` fields.
        """
        hops: List[Dict[str, Any]] = []
        for line in output.splitlines():
            hop = self._parse_hop_line(line)
            if hop is not None:
                hops.append(hop)
        return hops

    def _parse_hop_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a single traceroute output line.

        Args:
            line: One line of traceroute output.

        Returns:
            Hop dict or ``None`` if the line is not a valid hop.
        """
        if self._is_windows:
            return self._parse_tracert_line(line)
        return self._parse_traceroute_line(line)

    @staticmethod
    def _parse_traceroute_line(line: str) -> Optional[Dict[str, Any]]:
        """Parse a Unix traceroute output line.

        Args:
            line: Raw traceroute line.

        Returns:
            Hop dict or ``None``.
        """
        m = _HOP_RE.match(line)
        if not m:
            return None
        hop_num = int(m.group(1))
        hostname = m.group(2) or None
        ip = m.group(3) or m.group(4) or None
        rtt = float(m.group(5)) if m.group(5) else None

        if not ip and "*" not in line and not hostname:
            return None

        return {
            "hop": hop_num,
            "ip": ip,
            "hostname": hostname,
            "rtt_ms": rtt,
            "no_response": ip is None,
        }

    @staticmethod
    def _parse_tracert_line(line: str) -> Optional[Dict[str, Any]]:
        """Parse a Windows tracert output line.

        Args:
            line: Raw tracert line.

        Returns:
            Hop dict or ``None``.
        """
        m = _TRACERT_RE.match(line)
        if not m:
            return None
        hop_num = int(m.group(1))
        host_or_ip = m.group(2)
        ip_match = re.match(r"^(\d+\.\d+\.\d+\.\d+)$", host_or_ip)
        ip = host_or_ip if ip_match else None
        hostname = host_or_ip if not ip_match else None
        return {
            "hop": hop_num,
            "ip": ip,
            "hostname": hostname,
            "rtt_ms": None,
            "no_response": False,
        }

    @staticmethod
    def _analyze_hops(hops: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyse hop list for network characteristics.

        Args:
            hops: Parsed hop list.

        Returns:
            Analysis dict with bottleneck and summary information.
        """
        responding_hops = [h for h in hops if h.get("ip")]
        rtts = [h["rtt_ms"] for h in responding_hops if h.get("rtt_ms") is not None]

        bottlenecks: List[Dict[str, Any]] = []
        for i in range(1, len(rtts)):
            delta = rtts[i] - rtts[i - 1]
            if delta > 50:
                bottlenecks.append({
                    "hop": responding_hops[i]["hop"],
                    "ip": responding_hops[i].get("ip"),
                    "rtt_increase_ms": round(delta, 2),
                })

        return {
            "total_responding_hops": len(responding_hops),
            "avg_rtt_ms": round(sum(rtts) / len(rtts), 2) if rtts else None,
            "max_rtt_ms": round(max(rtts), 2) if rtts else None,
            "bottlenecks": bottlenecks,
        }

    @staticmethod
    def _empty_result(target: str) -> Dict[str, Any]:
        """Return an empty traceroute result.

        Args:
            target: The traceroute target.

        Returns:
            Empty result dict.
        """
        return {
            "available": True,
            "target": target,
            "hops": [],
            "total_hops": 0,
            "analysis": {
                "total_responding_hops": 0,
                "avg_rtt_ms": None,
                "max_rtt_ms": None,
                "bottlenecks": [],
            },
        }
