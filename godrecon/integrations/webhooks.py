"""Webhook and SIEM integrations — push findings to external systems in real-time."""

from __future__ import annotations

import socket
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from godrecon.core.config import Config

_SEVERITY_COLORS_SLACK = {
    "critical": "#FF0000",
    "high": "#FF6600",
    "medium": "#FFCC00",
    "low": "#3399FF",
    "info": "#CCCCCC",
}

_SEVERITY_COLORS_DISCORD = {
    "critical": 0xFF0000,
    "high": 0xFF6600,
    "medium": 0xFFCC00,
    "low": 0x3399FF,
    "info": 0xCCCCCC,
}


class Integration:
    """Abstract base class for all notification integrations."""

    name: str = "base"

    async def send(self, event: dict) -> bool:
        """Send *event* to the external system.

        Args:
            event: Event payload dict.

        Returns:
            ``True`` on success, ``False`` on failure.
        """
        raise NotImplementedError


class WebhookIntegration(Integration):
    """Post JSON payloads to an arbitrary webhook URL.

    Args:
        url: Target webhook URL.
        headers: Optional extra HTTP headers.
        method: HTTP method (default ``"POST"``).
        retries: Number of retry attempts on failure.
    """

    name = "webhook"

    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        method: str = "POST",
        retries: int = 3,
    ) -> None:
        self.url = url
        self.headers = headers or {}
        self.method = method.upper()
        self.retries = retries

    async def send(self, event: dict) -> bool:
        import aiohttp

        headers = {"Content-Type": "application/json", **self.headers}
        for attempt in range(self.retries):
            try:
                async with (
                    aiohttp.ClientSession() as session,
                    session.request(
                        self.method,
                        self.url,
                        json=event,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as resp,
                ):
                    return resp.status < 400
            except Exception:  # noqa: BLE001
                if attempt == self.retries - 1:
                    return False
        return False


class SlackIntegration(Integration):
    """Send findings to a Slack channel via an Incoming Webhook.

    Args:
        webhook_url: Slack Incoming Webhook URL.
    """

    name = "slack"

    def __init__(self, webhook_url: str) -> None:
        self.webhook_url = webhook_url

    async def send(self, event: dict) -> bool:
        import aiohttp

        severity = event.get("severity", "info").lower()
        color = _SEVERITY_COLORS_SLACK.get(severity, "#CCCCCC")
        payload = {
            "attachments": [
                {
                    "color": color,
                    "title": event.get("title", "GODRECON Finding"),
                    "text": event.get("description", ""),
                    "fields": [
                        {"title": "Severity", "value": severity.upper(), "short": True},
                        {"title": "Target", "value": event.get("target", ""), "short": True},
                    ],
                    "footer": "GODRECON",
                }
            ]
        }
        try:
            async with (
                aiohttp.ClientSession() as session,
                session.post(
                    self.webhook_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp,
            ):
                return resp.status < 400
        except Exception:  # noqa: BLE001
            return False


class DiscordIntegration(Integration):
    """Send findings to a Discord channel via a webhook.

    Args:
        webhook_url: Discord webhook URL.
    """

    name = "discord"

    def __init__(self, webhook_url: str) -> None:
        self.webhook_url = webhook_url

    async def send(self, event: dict) -> bool:
        import aiohttp

        severity = event.get("severity", "info").lower()
        color = _SEVERITY_COLORS_DISCORD.get(severity, 0xCCCCCC)
        payload = {
            "embeds": [
                {
                    "title": event.get("title", "GODRECON Finding"),
                    "description": event.get("description", ""),
                    "color": color,
                    "fields": [
                        {"name": "Severity", "value": severity.upper(), "inline": True},
                        {"name": "Target", "value": event.get("target", ""), "inline": True},
                    ],
                    "footer": {"text": "GODRECON"},
                }
            ]
        }
        try:
            async with (
                aiohttp.ClientSession() as session,
                session.post(
                    self.webhook_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp,
            ):
                return resp.status < 400
        except Exception:  # noqa: BLE001
            return False


class SIEMIntegration(Integration):
    """Forward findings to a SIEM system.

    Supports:
    - CEF (Common Event Format) over UDP syslog.
    - JSON over HTTP (Splunk HEC).

    Args:
        endpoint: SIEM endpoint — either ``"syslog://host:port"`` or an HTTP(S) URL.
        format: ``"cef"`` or ``"json"`` (default ``"cef"``).
        token: Bearer / HEC token (for HTTP endpoints).
    """

    name = "siem"

    def __init__(self, endpoint: str, format: str = "cef", token: str = "") -> None:  # noqa: A002
        self.endpoint = endpoint
        self.format = format.lower()
        self.token = token

    @staticmethod
    def to_cef(event: dict) -> str:
        """Convert *event* to a CEF-formatted string.

        Args:
            event: Event payload dict.

        Returns:
            CEF string.
        """
        severity_map = {"critical": 10, "high": 8, "medium": 5, "low": 3, "info": 1}
        sev_str = event.get("severity", "info").lower()
        cef_sev = severity_map.get(sev_str, 1)
        name = event.get("title", "Finding").replace("|", "\\|")
        desc = event.get("description", "").replace("|", "\\|")
        target = event.get("target", "").replace("=", "\\=")
        return f"CEF:0|GODRECON|GODRECON|1.0|{name}|{desc}|{cef_sev}|dst={target} sev={sev_str}"

    async def send(self, event: dict) -> bool:
        if self.endpoint.startswith(("http://", "https://")):
            return await self._send_http(event)
        return self._send_syslog(event)

    async def _send_http(self, event: dict) -> bool:
        import aiohttp

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Splunk {self.token}"
        payload: Any = {"event": event} if "splunk" in self.endpoint.lower() else event
        try:
            async with (
                aiohttp.ClientSession() as session,
                session.post(
                    self.endpoint,
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp,
            ):
                return resp.status < 400
        except Exception:  # noqa: BLE001
            return False

    def _send_syslog(self, event: dict) -> bool:
        # Parse syslog://host:port
        addr_part = self.endpoint.removeprefix("syslog://")
        host, _, port_str = addr_part.rpartition(":")
        if not host:
            host = addr_part
            port_str = "514"
        try:
            port = int(port_str)
        except ValueError:
            port = 514
        message = self.to_cef(event) if self.format == "cef" else str(event)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(message.encode("utf-8"), (host, port))
            sock.close()
            return True
        except Exception:  # noqa: BLE001
            return False


class IntegrationManager:
    """Manage and dispatch events to multiple integrations.

    Example::

        manager = IntegrationManager()
        manager.register(SlackIntegration("https://hooks.slack.com/..."))
        await manager.notify_all({"title": "New finding", "severity": "high"})
    """

    def __init__(self) -> None:
        self._integrations: list[Integration] = []

    def register(self, integration: Integration) -> None:
        """Register an integration.

        Args:
            integration: :class:`Integration` instance to add.
        """
        self._integrations.append(integration)

    async def notify_all(self, event: dict) -> dict[str, bool]:
        """Send *event* to all registered integrations.

        Args:
            event: Event payload dict.

        Returns:
            Dict mapping integration name to success/failure boolean.
        """

        results: dict[str, bool] = {}
        tasks = [(integ.name, integ.send(event)) for integ in self._integrations]
        for name, coro in tasks:
            results[name] = await coro
        return results

    @classmethod
    def from_config(cls, config: Config) -> IntegrationManager:  # type: ignore[name-defined]
        """Build an :class:`IntegrationManager` from a :class:`~godrecon.core.config.Config`.

        Args:
            config: GODRECON configuration instance.

        Returns:
            Configured :class:`IntegrationManager`.
        """
        manager = cls()
        notif = config.notifications

        if notif.slack.enabled and notif.slack.webhook_url:
            manager.register(SlackIntegration(notif.slack.webhook_url))
        if notif.discord.enabled and notif.discord.webhook_url:
            manager.register(DiscordIntegration(notif.discord.webhook_url))
        if notif.webhook.enabled and notif.webhook.url:
            manager.register(WebhookIntegration(notif.webhook.url, headers=dict(notif.webhook.headers)))

        return manager
