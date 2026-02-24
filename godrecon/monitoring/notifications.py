"""Multi-platform notification system for GODRECON continuous monitoring.

Supports Slack, Discord, Telegram, Email (SMTP), and generic webhook backends.
All HTTP-based notifications use aiohttp for async HTTP calls.
"""

from __future__ import annotations

import asyncio
import json
import logging
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional

try:
    import aiohttp as _aiohttp
except ImportError:  # noqa: BLE001
    _aiohttp = None  # type: ignore[assignment]

from godrecon.monitoring.diff import DiffSummary

logger = logging.getLogger(__name__)

_SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}


def _format_message(
    target: str,
    scan_timestamp: str,
    diff: DiffSummary,
) -> str:
    """Build a plain-text alert message from a diff summary.

    Args:
        target: The scan target domain/IP.
        scan_timestamp: ISO timestamp string for the scan.
        diff: The :class:`~godrecon.monitoring.diff.DiffSummary` to format.

    Returns:
        Formatted multi-line string.
    """
    lines = [
        f"🔱 GODRECON Alert — {target}",
        f"Scan: {scan_timestamp}",
        "",
        f"New findings: {diff.total_new}  |  Resolved: {diff.total_resolved}",
    ]

    if diff.severity_counts:
        sev_parts = []
        for sev in ("critical", "high", "medium", "low", "info"):
            count = diff.severity_counts.get(sev, 0)
            if count:
                emoji = _SEVERITY_EMOJI.get(sev, "")
                sev_parts.append(f"{emoji} {sev.capitalize()}: {count}")
        if sev_parts:
            lines.append("  " + "  ".join(sev_parts))

    if diff.new_findings:
        lines.append("")
        lines.append("Top new findings:")
        for f in diff.new_findings[:5]:
            emoji = _SEVERITY_EMOJI.get(f.severity.lower(), "")
            lines.append(f"  {emoji} [{f.severity.upper()}] {f.title}")

    if diff.new_subdomains:
        lines.append("")
        lines.append(f"New subdomains ({len(diff.new_subdomains)}):")
        for sub in diff.new_subdomains[:5]:
            lines.append(f"  • {sub}")
        if len(diff.new_subdomains) > 5:
            lines.append(f"  … and {len(diff.new_subdomains) - 5} more")

    if diff.new_ports:
        lines.append("")
        lines.append(f"New open ports ({len(diff.new_ports)}):")
        for port in diff.new_ports[:5]:
            lines.append(f"  • {port}")

    return "\n".join(lines)


class NotificationManager:
    """Manages and dispatches notifications across multiple backends.

    Configured via the ``notifications`` section of :class:`~godrecon.core.config.Config`.

    Example::

        manager = NotificationManager(cfg.notifications)
        await manager.notify(target="example.com", scan_timestamp="2024-01-01T00:00:00Z", diff=summary)
    """

    def __init__(self, notifications_cfg: Any) -> None:
        """Initialise with a :class:`~godrecon.core.config.NotificationsConfig`.

        Args:
            notifications_cfg: Parsed notifications configuration object.
        """
        self._cfg = notifications_cfg

    async def notify(
        self,
        target: str,
        scan_timestamp: str,
        diff: DiffSummary,
    ) -> None:
        """Dispatch notifications to all enabled backends.

        Failures in individual backends are logged but do not propagate.

        Args:
            target: Scan target identifier.
            scan_timestamp: ISO 8601 timestamp string.
            diff: Diff summary to report.
        """
        message = _format_message(target, scan_timestamp, diff)
        tasks = []

        cfg = self._cfg
        if getattr(cfg.slack, "enabled", False):
            tasks.append(self._send_slack(cfg.slack, message))
        if getattr(cfg.discord, "enabled", False):
            tasks.append(self._send_discord(cfg.discord, message))
        if getattr(cfg.telegram, "enabled", False):
            tasks.append(self._send_telegram(cfg.telegram, message))
        if getattr(cfg.email, "enabled", False):
            tasks.append(self._send_email(cfg.email, target, message))
        if getattr(cfg.webhook, "enabled", False):
            tasks.append(
                self._send_webhook(
                    cfg.webhook,
                    target,
                    scan_timestamp,
                    diff,
                    message,
                )
            )

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.warning("Notification backend %d failed: %s", i, result)

    # ------------------------------------------------------------------
    # Backend implementations
    # ------------------------------------------------------------------

    async def _send_slack(self, cfg: Any, message: str) -> None:
        """Send a Slack webhook notification.

        Args:
            cfg: Slack configuration object.
            message: Formatted alert message.
        """
        if _aiohttp is None:
            raise RuntimeError("aiohttp is required for Slack notifications")
        payload = {"text": message}
        async with _aiohttp.ClientSession() as session:
            async with session.post(
                cfg.webhook_url,
                json=payload,
                timeout=_aiohttp.ClientTimeout(total=10),
            ) as resp:
                resp.raise_for_status()

    async def _send_discord(self, cfg: Any, message: str) -> None:
        """Send a Discord webhook notification.

        Args:
            cfg: Discord configuration object.
            message: Formatted alert message.
        """
        if _aiohttp is None:
            raise RuntimeError("aiohttp is required for Discord notifications")
        payload = {"content": message}
        async with _aiohttp.ClientSession() as session:
            async with session.post(
                cfg.webhook_url,
                json=payload,
                timeout=_aiohttp.ClientTimeout(total=10),
            ) as resp:
                resp.raise_for_status()

    async def _send_telegram(self, cfg: Any, message: str) -> None:
        """Send a Telegram Bot API notification.

        Args:
            cfg: Telegram configuration object.
            message: Formatted alert message.
        """
        if _aiohttp is None:
            raise RuntimeError("aiohttp is required for Telegram notifications")
        url = f"https://api.telegram.org/bot{cfg.bot_token}/sendMessage"
        payload = {"chat_id": cfg.chat_id, "text": message}
        async with _aiohttp.ClientSession() as session:
            async with session.post(
                url,
                json=payload,
                timeout=_aiohttp.ClientTimeout(total=10),
            ) as resp:
                resp.raise_for_status()

    async def _send_email(self, cfg: Any, target: str, message: str) -> None:
        """Send an email notification via SMTP using a thread executor.

        Args:
            cfg: Email configuration object.
            target: Scan target for the subject line.
            message: Formatted alert message body.
        """
        def _send() -> None:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"GODRECON Alert — {target}"
            msg["From"] = cfg.from_addr
            msg["To"] = ", ".join(cfg.to_addrs)
            msg.attach(MIMEText(message, "plain"))

            context = ssl.create_default_context()
            with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port) as server:
                server.ehlo()
                server.starttls(context=context)
                if cfg.smtp_user:
                    server.login(cfg.smtp_user, cfg.smtp_pass)
                server.sendmail(cfg.from_addr, cfg.to_addrs, msg.as_string())

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _send)

    async def _send_webhook(
        self,
        cfg: Any,
        target: str,
        scan_timestamp: str,
        diff: DiffSummary,
        message: str,
    ) -> None:
        """Send a generic JSON webhook notification.

        Args:
            cfg: Webhook configuration object.
            target: Scan target.
            scan_timestamp: ISO timestamp string.
            diff: Diff summary for structured payload.
            message: Formatted text message.
        """
        if _aiohttp is None:
            raise RuntimeError("aiohttp is required for webhook notifications")
        payload: Dict[str, Any] = {
            "target": target,
            "scan_timestamp": scan_timestamp,
            "message": message,
            "new_findings": diff.total_new,
            "resolved_findings": diff.total_resolved,
            "severity_counts": diff.severity_counts,
            "new_subdomains": diff.new_subdomains[:20],
            "new_ports": diff.new_ports[:20],
        }
        headers = dict(cfg.headers) if cfg.headers else {}
        async with _aiohttp.ClientSession() as session:
            async with session.post(
                cfg.url,
                json=payload,
                headers=headers,
                timeout=_aiohttp.ClientTimeout(total=10),
            ) as resp:
                resp.raise_for_status()
