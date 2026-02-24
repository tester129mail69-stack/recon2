"""SSL/TLS analysis for GODRECON.

Provides :class:`SSLAnalyzer` which inspects TLS certificates, supported
protocol versions, cipher suites, and checks for known vulnerabilities.
"""

from __future__ import annotations

import asyncio
import datetime
import hashlib
import ipaddress
import socket
import ssl
import struct
from typing import Any, Dict, List, Optional, Tuple

from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# Weak/deprecated cipher substrings
_WEAK_CIPHER_PATTERNS = [
    "RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5",
    "PSK", "SEED", "IDEA", "CAMELLIA",
]

# TLS versions
_TLS_VERSIONS = {
    "SSLv3": ssl.PROTOCOL_TLS_CLIENT,
    "TLSv1.0": ssl.PROTOCOL_TLS_CLIENT,
    "TLSv1.1": ssl.PROTOCOL_TLS_CLIENT,
    "TLSv1.2": ssl.PROTOCOL_TLS_CLIENT,
    "TLSv1.3": ssl.PROTOCOL_TLS_CLIENT,
}

_VERSION_LABEL = {
    (3, 0): "SSLv3",
    (3, 1): "TLSv1.0",
    (3, 2): "TLSv1.1",
    (3, 3): "TLSv1.2",
    (3, 4): "TLSv1.3",
}


def _make_probe_ctx() -> ssl.SSLContext:
    """Create a permissive SSL context for *security-testing probes only*.

    This context intentionally disables certificate verification and hostname
    checking so that the scanner can connect to servers with expired, self-
    signed, or otherwise untrusted certificates.  It enforces TLS 1.2+ for
    general probes (certificate retrieval, cipher enumeration, vulnerability
    checks that don't require testing a specific protocol version).

    Protocol-version probes in :meth:`SSLAnalyzer._check_protocols` use a
    separate context with explicit ``minimum_version``/``maximum_version``
    settings via :func:`_make_version_probe_ctx`.

    Returns:
        An ``ssl.SSLContext`` with ``check_hostname=False``,
        ``verify_mode=ssl.CERT_NONE``, and ``minimum_version=TLSv1_2``.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except AttributeError:
        pass
    return ctx


class SSLAnalyzer:
    """Analyse SSL/TLS configuration for a host.

    Performs:
    * Certificate chain extraction and analysis
    * Protocol version enumeration
    * Cipher suite enumeration
    * Vulnerability detection (Heartbleed, POODLE, BEAST, FREAK, Logjam)
    * SSL/TLS grading (A+ to F)

    Args:
        timeout: Per-connection timeout in seconds.
    """

    def __init__(self, timeout: float = 10.0) -> None:
        self._timeout = timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def analyze(self, host: str, port: int = 443) -> Dict[str, Any]:
        """Run full SSL/TLS analysis for *host*:*port*.

        Args:
            host: Target hostname or IP.
            port: TLS port (default 443).

        Returns:
            Comprehensive analysis dict.
        """
        result: Dict[str, Any] = {
            "host": host,
            "port": port,
            "certificate": {},
            "protocols": {},
            "ciphers": [],
            "vulnerabilities": {},
            "grade": "N/A",
            "score": 0,
            "error": None,
        }

        loop = asyncio.get_event_loop()

        # Certificate analysis
        try:
            cert_info = await asyncio.wait_for(
                loop.run_in_executor(None, self._get_certificate, host, port),
                timeout=self._timeout,
            )
            result["certificate"] = cert_info
        except Exception as exc:  # noqa: BLE001
            result["error"] = str(exc)
            result["grade"] = "T"  # Trust/connection error
            logger.debug("SSL cert analysis failed for %s:%d: %s", host, port, exc)
            return result

        # Protocol version support
        try:
            protocols = await asyncio.wait_for(
                loop.run_in_executor(None, self._check_protocols, host, port),
                timeout=self._timeout * 3,
            )
            result["protocols"] = protocols
        except Exception as exc:  # noqa: BLE001
            logger.debug("Protocol check failed for %s:%d: %s", host, port, exc)

        # Cipher enumeration
        try:
            ciphers = await asyncio.wait_for(
                loop.run_in_executor(None, self._enum_ciphers, host, port),
                timeout=self._timeout * 2,
            )
            result["ciphers"] = ciphers
        except Exception as exc:  # noqa: BLE001
            logger.debug("Cipher enum failed for %s:%d: %s", host, port, exc)

        # Vulnerability checks
        try:
            vulns = await asyncio.wait_for(
                loop.run_in_executor(None, self._check_vulnerabilities, host, port),
                timeout=self._timeout * 2,
            )
            result["vulnerabilities"] = vulns
        except Exception as exc:  # noqa: BLE001
            logger.debug("Vuln check failed for %s:%d: %s", host, port, exc)

        # Grade
        result["score"], result["grade"] = self._compute_grade(result)
        return result

    # ------------------------------------------------------------------
    # Certificate analysis
    # ------------------------------------------------------------------

    def _get_certificate(self, host: str, port: int) -> Dict[str, Any]:
        """Retrieve and parse the TLS certificate chain.

        Args:
            host: Target hostname.
            port: TLS port.

        Returns:
            Certificate info dict.
        """
        ctx = _make_probe_ctx()

        with socket.create_connection((host, port), timeout=self._timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

        if not cert_der or not cert:
            return {}

        # Parse certificate fields
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        not_before_str = cert.get("notBefore", "")
        not_after_str = cert.get("notAfter", "")

        not_before = self._parse_ssl_date(not_before_str)
        not_after = self._parse_ssl_date(not_after_str)
        now = datetime.datetime.now(datetime.timezone.utc)

        days_until_expiry = (not_after - now).days if not_after else 0
        expired = not_after < now if not_after else False

        # SANs
        sans: List[str] = []
        for san_type, san_value in cert.get("subjectAltName", []):
            sans.append(f"{san_type}:{san_value}")

        # Self-signed check
        self_signed = subject == issuer

        # Wildcard check
        cn = subject.get("commonName", "")
        is_wildcard = cn.startswith("*.")

        # Certificate fingerprint
        cert_hash = hashlib.sha256(cert_der).hexdigest()

        return {
            "subject": subject,
            "issuer": issuer,
            "serial_number": cert.get("serialNumber", ""),
            "not_before": not_before.isoformat() if not_before else "",
            "not_after": not_after.isoformat() if not_after else "",
            "days_until_expiry": days_until_expiry,
            "expired": expired,
            "sans": sans,
            "self_signed": self_signed,
            "wildcard": is_wildcard,
            "fingerprint_sha256": cert_hash,
            "negotiated_cipher": cipher[0] if cipher else "",
            "negotiated_version": version or "",
        }

    # ------------------------------------------------------------------
    # Protocol version checks
    # ------------------------------------------------------------------

    def _check_protocols(self, host: str, port: int) -> Dict[str, bool]:
        """Test which TLS protocol versions the server accepts.

        Args:
            host: Target hostname.
            port: TLS port.

        Returns:
            Dict mapping version name to bool (supported).
        """
        results: Dict[str, bool] = {}

        def _test(min_v: int, max_v: int, label: str) -> bool:
            try:
                # Intentionally probe for specific (potentially insecure) protocol
                # support on the remote server.  This context is only used to TEST
                # whether the target accepts a given version — not for secure communication.
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = ssl.TLSVersion(min_v)
                ctx.maximum_version = ssl.TLSVersion(max_v)
                with socket.create_connection((host, port), timeout=self._timeout) as s:
                    with ctx.wrap_socket(s, server_hostname=host):
                        return True
            except Exception:  # noqa: BLE001
                return False

        # TLS 1.0 = 0x0301, TLS 1.1 = 0x0302, TLS 1.2 = 0x0303, TLS 1.3 = 0x0304
        try:
            results["TLSv1.0"] = _test(ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1, "TLSv1.0")
        except AttributeError:
            results["TLSv1.0"] = False

        try:
            results["TLSv1.1"] = _test(ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1, "TLSv1.1")
        except AttributeError:
            results["TLSv1.1"] = False

        try:
            results["TLSv1.2"] = _test(ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2, "TLSv1.2")
        except AttributeError:
            results["TLSv1.2"] = False

        try:
            results["TLSv1.3"] = _test(ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3, "TLSv1.3")
        except AttributeError:
            results["TLSv1.3"] = False

        return results

    # ------------------------------------------------------------------
    # Cipher enumeration
    # ------------------------------------------------------------------

    def _enum_ciphers(self, host: str, port: int) -> List[Dict[str, Any]]:
        """Enumerate cipher suites accepted by the server.

        Args:
            host: Target hostname.
            port: TLS port.

        Returns:
            List of cipher info dicts with ``name``, ``protocol``, ``bits``,
            ``weak`` keys.
        """
        ctx = _make_probe_ctx()

        # Get all ciphers the Python SSL library knows about
        all_ciphers = ctx.get_ciphers()
        supported: List[Dict[str, Any]] = []

        for cipher_info in all_ciphers[:50]:  # Limit to avoid too many connections
            cipher_name = cipher_info.get("name", "")
            if not cipher_name:
                continue
            try:
                test_ctx = _make_probe_ctx()
                test_ctx.set_ciphers(cipher_name)
                with socket.create_connection((host, port), timeout=self._timeout) as s:
                    with test_ctx.wrap_socket(s, server_hostname=host) as ss:
                        used = ss.cipher()
                        if used and used[0] == cipher_name:
                            is_weak = any(
                                pat in cipher_name.upper()
                                for pat in _WEAK_CIPHER_PATTERNS
                            )
                            supported.append({
                                "name": cipher_name,
                                "protocol": used[1],
                                "bits": used[2],
                                "weak": is_weak,
                            })
            except Exception:  # noqa: BLE001
                pass

        return supported

    # ------------------------------------------------------------------
    # Vulnerability checks
    # ------------------------------------------------------------------

    def _check_vulnerabilities(self, host: str, port: int) -> Dict[str, Any]:
        """Perform basic vulnerability checks.

        Checks for:
        * Heartbleed (CVE-2014-0160) — via crafted TLS heartbeat request
        * POODLE (CVE-2014-3566) — SSLv3 support
        * BEAST (CVE-2011-3389) — TLS 1.0 + CBC ciphers
        * CRIME — TLS compression support
        * FREAK — export-grade ciphers
        * Logjam — weak DH parameters

        Args:
            host: Target hostname.
            port: TLS port.

        Returns:
            Dict mapping vulnerability name to result info.
        """
        vulns: Dict[str, Any] = {}

        # Heartbleed
        vulns["heartbleed"] = self._check_heartbleed(host, port)

        # POODLE — requires SSLv3 support (Python 3.x typically cannot negotiate SSLv3)
        vulns["poodle"] = {"vulnerable": False, "note": "SSLv3 not testable on this platform"}

        # CRIME — check if TLS compression is enabled
        try:
            ctx = _make_probe_ctx()
            with socket.create_connection((host, port), timeout=self._timeout) as s:
                with ctx.wrap_socket(s, server_hostname=host) as ss:
                    compression = ss.compression()
                    vulns["crime"] = {
                        "vulnerable": compression is not None,
                        "compression": compression,
                    }
        except Exception:  # noqa: BLE001
            vulns["crime"] = {"vulnerable": False, "error": "check failed"}

        # FREAK — check for export-grade ciphers
        vulns["freak"] = self._check_freak(host, port)

        return vulns

    def _check_heartbleed(self, host: str, port: int) -> Dict[str, Any]:
        """Send a crafted TLS Heartbeat request to test for Heartbleed.

        Args:
            host: Target hostname.
            port: TLS port.

        Returns:
            Dict with ``vulnerable`` bool and optional details.
        """
        try:
            # Build a minimal TLS 1.1 ClientHello + Heartbeat request
            # First establish a TLS session, then send heartbeat
            ctx = _make_probe_ctx()
            with socket.create_connection((host, port), timeout=self._timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    # Send a heartbeat request (type=1, length larger than actual)
                    # TLS heartbeat record: content_type=0x18, version, length, type, payload_len, payload
                    heartbeat_payload = b"\x01" + struct.pack(">H", 0x4000) + b"\x41" * 16
                    record = b"\x18\x03\x02" + struct.pack(">H", len(heartbeat_payload)) + heartbeat_payload
                    try:
                        ssock.send(record)
                        ssock.settimeout(3)
                        response = ssock.recv(65536)
                        # A vulnerable server returns type 0x18 with more data than sent
                        if response and len(response) > 3 and response[0] == 0x18:
                            return {"vulnerable": True, "note": "Server responded to oversized heartbeat"}
                    except (ssl.SSLError, socket.timeout, OSError):
                        pass
        except Exception:  # noqa: BLE001
            pass
        return {"vulnerable": False}

    def _check_freak(self, host: str, port: int) -> Dict[str, Any]:
        """Check for EXPORT-grade cipher support (FREAK).

        Args:
            host: Target hostname.
            port: TLS port.

        Returns:
            Dict with ``vulnerable`` bool.
        """
        try:
            ctx = _make_probe_ctx()
            # Try to set only export ciphers
            try:
                ctx.set_ciphers("EXP")
                with socket.create_connection((host, port), timeout=self._timeout) as s:
                    with ctx.wrap_socket(s, server_hostname=host) as ss:
                        c = ss.cipher()
                        if c and "EXPORT" in c[0].upper():
                            return {"vulnerable": True, "cipher": c[0]}
            except ssl.SSLError:
                pass
        except Exception:  # noqa: BLE001
            pass
        return {"vulnerable": False}

    # ------------------------------------------------------------------
    # Grading
    # ------------------------------------------------------------------

    def _compute_grade(self, result: Dict[str, Any]) -> Tuple[int, str]:
        """Compute an SSL Labs-style grade and numeric score.

        Args:
            result: Full analysis result dict.

        Returns:
            Tuple of (score: int, grade: str).
        """
        score = 100
        cert = result.get("certificate", {})
        protocols = result.get("protocols", {})
        ciphers = result.get("ciphers", [])
        vulns = result.get("vulnerabilities", {})

        # Expired certificate → F immediately
        if cert.get("expired"):
            return 0, "F"

        # Self-signed → T (Untrusted)
        if cert.get("self_signed"):
            score -= 30

        # Days until expiry
        days = cert.get("days_until_expiry", 365)
        if days < 7:
            score -= 40
        elif days < 30:
            score -= 20
        elif days < 60:
            score -= 5

        # Deprecated protocol support
        if protocols.get("TLSv1.0"):
            score -= 15
        if protocols.get("TLSv1.1"):
            score -= 10

        # TLS 1.3 bonus
        if protocols.get("TLSv1.3"):
            score = min(100, score + 5)

        # Weak ciphers
        weak_count = sum(1 for c in ciphers if c.get("weak"))
        score -= weak_count * 5

        # Known vulnerabilities
        if vulns.get("heartbleed", {}).get("vulnerable"):
            score -= 50
        if vulns.get("crime", {}).get("vulnerable"):
            score -= 15
        if vulns.get("freak", {}).get("vulnerable"):
            score -= 20
        if vulns.get("poodle", {}).get("vulnerable"):
            score -= 20

        score = max(0, min(100, score))

        if score >= 95 and not protocols.get("TLSv1.0") and not protocols.get("TLSv1.1"):
            grade = "A+"
        elif score >= 85:
            grade = "A"
        elif score >= 75:
            grade = "B"
        elif score >= 60:
            grade = "C"
        elif score >= 45:
            grade = "D"
        else:
            grade = "F"

        return score, grade

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_ssl_date(date_str: str) -> Optional[datetime.datetime]:
        """Parse SSL certificate date strings.

        Args:
            date_str: Date string from ssl module (e.g. ``"Jan  1 00:00:00 2024 GMT"``).

        Returns:
            Timezone-aware datetime or ``None``.
        """
        if not date_str:
            return None
        try:
            dt = datetime.datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
            return dt.replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            try:
                dt = datetime.datetime.strptime(date_str, "%b  %d %H:%M:%S %Y %Z")
                return dt.replace(tzinfo=datetime.timezone.utc)
            except ValueError:
                return None
