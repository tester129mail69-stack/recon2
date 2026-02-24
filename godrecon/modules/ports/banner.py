"""Service banner grabbing for GODRECON port scanning.

Connects to open ports and retrieves service banners using
protocol-appropriate probes.
"""

from __future__ import annotations

import asyncio
from typing import Optional


# Port sets grouped by protocol behaviour
_HTTP_PORTS = {80, 8080, 8000, 8008, 8888, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090}
_FTP_PORTS = {21}
_SSH_PORTS = {22}
_SMTP_PORTS = {25, 465, 587}
_POP3_PORTS = {110, 995}
_IMAP_PORTS = {143, 993}
_MYSQL_PORTS = {3306}
_REDIS_PORTS = {6379}
_TELNET_PORTS = {23}

_READ_SIZE = 4096


class BannerGrabber:
    """Grab service banners from open TCP ports.

    Uses protocol-specific probes where possible and falls back to a
    passive read or an empty probe for unknown services.

    Args:
        timeout: Per-operation socket timeout in seconds.
    """

    def __init__(self, timeout: float = 5.0) -> None:
        self.timeout = timeout

    async def grab(self, host: str, port: int) -> Optional[str]:
        """Connect to *host*:*port* and return the service banner.

        Args:
            host: Target hostname or IP address.
            port: TCP port number.

        Returns:
            Decoded banner string, or ``None`` on any error.
        """
        try:
            return await asyncio.wait_for(
                self._grab(host, port),
                timeout=self.timeout,
            )
        except Exception:  # noqa: BLE001
            return None

    async def _grab(self, host: str, port: int) -> Optional[str]:
        """Internal grab logic without timeout wrapper."""
        reader, writer = await asyncio.open_connection(host, port)
        try:
            raw = await self._exchange(port, reader, writer)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

        if not raw:
            return None
        return raw.decode("utf-8", errors="replace").replace("\x00", "").strip()

    async def _exchange(
        self,
        port: int,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> bytes:
        """Send a probe (if needed) and read the response.

        Args:
            port: Destination port — used to choose the probe type.
            reader: Async stream reader.
            writer: Async stream writer.

        Returns:
            Raw bytes received from the service.
        """
        if port in _HTTP_PORTS:
            writer.write(b"GET / HTTP/1.0\r\n\r\n")
            await writer.drain()
            return await reader.read(_READ_SIZE)

        if port in _FTP_PORTS or port in _SSH_PORTS:
            return await reader.read(_READ_SIZE)

        if port in _SMTP_PORTS:
            return await reader.read(_READ_SIZE)

        if port in _POP3_PORTS:
            return await reader.read(_READ_SIZE)

        if port in _IMAP_PORTS:
            return await reader.read(_READ_SIZE)

        if port in _MYSQL_PORTS:
            return await reader.read(_READ_SIZE)

        if port in _REDIS_PORTS:
            writer.write(b"PING\r\n")
            await writer.drain()
            return await reader.read(_READ_SIZE)

        if port in _TELNET_PORTS:
            return await reader.read(_READ_SIZE)

        # Default: try passive read first; send empty probe if nothing arrives.
        try:
            data = await asyncio.wait_for(reader.read(_READ_SIZE), timeout=2.0)
            if data:
                return data
        except asyncio.TimeoutError:
            pass

        writer.write(b"\r\n")
        await writer.drain()
        return await reader.read(_READ_SIZE)
