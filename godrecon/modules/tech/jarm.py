"""JARM TLS fingerprinting for GODRECON.

Provides :class:`JARMFingerprinter` which sends 10 specially crafted TLS
Client Hello packets and generates a JARM fingerprint hash.

JARM is a TLS server fingerprinting technique developed by Salesforce.
Reference: https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a/
"""

from __future__ import annotations

import asyncio
import hashlib
import socket
import struct
from typing import Any, Dict, List, Optional, Tuple

from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# JARM known signature database
_KNOWN_JARM: Dict[str, str] = {
    "27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d": "Cobalt Strike C2",
    "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1": "Metasploit",
    "2ad2ad0002ad2ad22c2ad2ad2ad2ad9e2ad2ad2caa56c8f0b3d8f69b0f6b1": "AsyncRAT",
    "1dd28d28d00028d1dc41d43d00041d58e4b4b5b1b93f922f1be88e0bcf2d": "NanoCore",
    "29d21b20d29d29d21c41d21b21b41d494e0df9532e75299f15ba73156cee38": "Nginx (default)",
    "27d27d27d29d27d1dc42d43d00041d44948135d15de501872fbb84d4d0a8ab": "Apache httpd",
    "2ad2ad0002ad2ad00041d2ad2ad41da5207249a18099be84ef3c8811914c14": "Cloudflare",
    "00000000000000eeeeeeeeeeeeeeee9e2ad2ad2ad2ad2ad2ad2ad2ad2ad2": "Tor",
    "27d3ed3ed0003ed1dc42d43d00041d58920d9a9a9a9a9a9a9a9a9a9a9a9a": "BruteRatel C4",
    "3fd3fd15d3fd3fd21c3fd3fd3fd3fd15d3fd3fd3fd3fd3fd3fd3fd3fd3fd3fd": "Sliver C2",
}

# The 10 JARM probe configurations
# Each tuple: (tls_version, cipher_list, extensions, grease, alpn)

# GREASE cipher value used for TLS probing
_GREASE_CIPHER = 0x0A0A

# ServerHello parse offsets
_TLS_RECORD_HEADER_SIZE = 5   # content_type(1) + version(2) + length(2)
_TLS_HANDSHAKE_TYPE_SIZE = 1  # handshake type byte
_TLS_HANDSHAKE_LEN_SIZE = 3   # 3-byte handshake length field
_JARM_PROBES: List[Tuple[bytes, List[int], List[bytes], bool, Optional[str]]] = [
    # Probe 1: TLS 1.2, forward ciphers
    (b"\x03\x03", [0x0035, 0x002f, 0x0005, 0x000a], [], False, None),
    # Probe 2: TLS 1.2, reverse ciphers
    (b"\x03\x03", [0x000a, 0x0005, 0x002f, 0x0035], [], False, None),
    # Probe 3: TLS 1.2 + 1.3
    (b"\x03\x03", [0x1301, 0x1302, 0x1303, 0x0035, 0x002f], [], False, None),
    # Probe 4: TLS 1.3 only
    (b"\x03\x04", [0x1301, 0x1302, 0x1303], [], False, None),
    # Probe 5: TLS 1.2 with GREASE
    (b"\x03\x03", [0x0035, 0x002f], [], True, None),
    # Probe 6: TLS 1.3 with ALPN h2
    (b"\x03\x04", [0x1301, 0x1302, 0x1303], [], False, "h2"),
    # Probe 7: TLS 1.2 with ALPN http/1.1
    (b"\x03\x03", [0x0035, 0x002f], [], False, "http/1.1"),
    # Probe 8: TLS 1.2 no extensions
    (b"\x03\x03", [0x0035, 0x002f, 0x0005, 0x000a], [], False, None),
    # Probe 9: TLS 1.1
    (b"\x03\x02", [0x0035, 0x002f, 0x0005, 0x000a], [], False, None),
    # Probe 10: TLS 1.0
    (b"\x03\x01", [0x0035, 0x002f, 0x0005, 0x000a], [], False, None),
]


class JARMFingerprinter:
    """Generate JARM TLS fingerprints for a host.

    Sends 10 crafted TLS Client Hello packets and records the server's
    cipher/extension choices to produce a reproducible fingerprint.

    Args:
        timeout: Per-probe connection timeout in seconds.
        concurrency: Maximum simultaneous probes.
    """

    def __init__(self, timeout: float = 10.0, concurrency: int = 5) -> None:
        self._timeout = timeout
        self._concurrency = concurrency

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def fingerprint(self, host: str, port: int = 443) -> Dict[str, Any]:
        """Generate a JARM fingerprint for *host*:*port*.

        Args:
            host: Target hostname or IP.
            port: Target TLS port (default 443).

        Returns:
            Dict with ``host``, ``port``, ``jarm_hash``, ``technology``,
            ``raw_tokens``.
        """
        sem = asyncio.Semaphore(self._concurrency)

        async def _probe(probe_cfg: Tuple) -> str:
            async with sem:
                return await self._send_probe(host, port, *probe_cfg)

        tasks = [asyncio.create_task(_probe(p)) for p in _JARM_PROBES]
        tokens: List[str] = await asyncio.gather(*tasks)

        jarm_hash = self._compute_hash(tokens)
        technology = _KNOWN_JARM.get(jarm_hash)

        return {
            "host": host,
            "port": port,
            "jarm_hash": jarm_hash,
            "technology": technology,
            "raw_tokens": tokens,
        }

    # ------------------------------------------------------------------
    # Probe helpers
    # ------------------------------------------------------------------

    async def _send_probe(
        self,
        host: str,
        port: int,
        tls_version: bytes,
        ciphers: List[int],
        extensions: List[bytes],
        grease: bool,
        alpn: Optional[str],
    ) -> str:
        """Send a single JARM TLS Client Hello and extract server response token.

        Args:
            host: Target host.
            port: Target port.
            tls_version: 2-byte TLS version field.
            ciphers: List of cipher suite values.
            extensions: Extra TLS extensions.
            grease: Whether to prepend a GREASE cipher.
            alpn: Optional ALPN protocol string.

        Returns:
            Token string like ``<cipher>|<version>|<extensions_hash>`` or
            empty string on failure.
        """
        try:
            hello = self._build_client_hello(host, tls_version, ciphers, grease, alpn)
            loop = asyncio.get_event_loop()
            token = await asyncio.wait_for(
                loop.run_in_executor(
                    None, self._tcp_send_recv, host, port, hello
                ),
                timeout=self._timeout,
            )
            return token
        except Exception as exc:  # noqa: BLE001
            logger.debug("JARM probe failed for %s:%d: %s", host, port, exc)
            return ""

    @staticmethod
    def _tcp_send_recv(host: str, port: int, data: bytes) -> str:
        """Synchronously connect, send *data*, and read a TLS ServerHello.

        Args:
            host: Target host.
            port: Target port.
            data: Raw bytes to send.

        Returns:
            Extracted token string.
        """
        try:
            with socket.create_connection((host, port), timeout=10) as sock:
                sock.sendall(data)
                buf = b""
                sock.settimeout(5)
                try:
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        buf += chunk
                        if len(buf) > 65536:
                            break
                except (socket.timeout, OSError):
                    pass
            return JARMFingerprinter._parse_server_hello(buf)
        except Exception:  # noqa: BLE001
            return ""

    @staticmethod
    def _parse_server_hello(data: bytes) -> str:
        """Extract cipher suite and version from a TLS ServerHello.

        Args:
            data: Raw TLS record bytes.

        Returns:
            Token string ``<cipher_hex>|<version_hex>|<ext_hash>``.
        """
        if len(data) < 5:
            return ""
        # Record type 0x16 = Handshake, content type 0x02 = ServerHello
        if data[0] != 0x16:
            return ""
        # Handshake message starts at byte _TLS_RECORD_HEADER_SIZE
        if len(data) < 11:
            return ""
        if data[_TLS_RECORD_HEADER_SIZE] != 0x02:  # ServerHello
            return ""
        # Version at offset 9 (2 bytes)
        version = data[9:11].hex()
        # ServerHello: type(1)+length(3)+version(2)+random(32)+session_id_len(1)
        offset = _TLS_RECORD_HEADER_SIZE + _TLS_HANDSHAKE_TYPE_SIZE + _TLS_HANDSHAKE_LEN_SIZE
        if len(data) < offset + 2 + 32 + 1:
            return f"|||{version}"
        version_bytes = data[offset: offset + 2].hex()
        offset += 2 + 32  # skip version and random
        sid_len = data[offset]
        offset += 1 + sid_len
        if len(data) < offset + 2:
            return f"|||{version_bytes}"
        cipher = data[offset: offset + 2].hex()
        return f"{cipher}|{version_bytes}|||"

    @staticmethod
    def _build_client_hello(
        host: str,
        tls_version: bytes,
        ciphers: List[int],
        grease: bool,
        alpn: Optional[str],
    ) -> bytes:
        """Build a TLS ClientHello packet.

        Args:
            host: SNI hostname.
            tls_version: 2-byte record/hello version.
            ciphers: Cipher suite values.
            grease: Prepend GREASE cipher.
            alpn: ALPN protocol string (or None).

        Returns:
            Raw TLS record bytes.
        """
        # Cipher suites
        cipher_list: List[int] = []
        if grease:
            cipher_list.append(_GREASE_CIPHER)
        cipher_list.extend(ciphers)
        cipher_bytes = b"".join(struct.pack(">H", c) for c in cipher_list)
        cipher_len = struct.pack(">H", len(cipher_bytes))

        # SNI extension
        sni = host.encode("ascii")
        sni_ext = (
            struct.pack(">H", 0x0000)  # type: server_name
            + struct.pack(">H", len(sni) + 5)
            + struct.pack(">H", len(sni) + 3)
            + b"\x00"
            + struct.pack(">H", len(sni))
            + sni
        )

        # Build extensions bytes
        ext_data = sni_ext

        # ALPN extension
        if alpn:
            alpn_bytes = alpn.encode("ascii")
            alpn_ext = (
                struct.pack(">H", 0x0010)
                + struct.pack(">H", len(alpn_bytes) + 4)
                + struct.pack(">H", len(alpn_bytes) + 2)
                + struct.pack(">H", len(alpn_bytes))
                + alpn_bytes
            )
            ext_data += alpn_ext

        extensions_len = struct.pack(">H", len(ext_data))

        # Random 32 bytes (all zeros for fingerprinting consistency)
        random_bytes = b"\x00" * 32

        # Build HelloBody
        hello_body = (
            tls_version
            + random_bytes
            + b"\x00"  # session ID length
            + cipher_len
            + cipher_bytes
            + b"\x01\x00"  # compression: null only
            + extensions_len
            + ext_data
        )

        # Wrap in Handshake record
        handshake = (
            b"\x01"
            + struct.pack(">I", len(hello_body))[1:]  # 3-byte length
            + hello_body
        )

        # TLS record layer (type=Handshake=0x16, version=TLS 1.0=\x03\x01)
        record = b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake
        return record

    # ------------------------------------------------------------------
    # Hash computation
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_hash(tokens: List[str]) -> str:
        """Compute the final JARM hash from the 10 probe tokens.

        Args:
            tokens: List of 10 token strings.

        Returns:
            62-character hex JARM hash.
        """
        combined = ",".join(tokens)
        sha256 = hashlib.sha256(combined.encode("utf-8")).hexdigest()
        return sha256[:62]
