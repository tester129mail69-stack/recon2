"""Telegram notification utility for GODRECON.

Full scan lifecycle alerts:
  - Scan started
  - Subdomain discovery complete
  - Per-target scan started / finished
  - Every vuln / CVE finding (with full detail)
  - Final master summary report

Setup:
  1. Create a bot via @BotFather → get bot_token
  2. Get your chat_id: https://api.telegram.org/bot<TOKEN>/getUpdates
  3. Add to config.yaml:
       notifications:
         telegram:
           enabled: true
           bot_token: "1234567890:ABC..."
           chat_id: "987654321"
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional

import aiohttp
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_TELEGRAM_API    = "https://api.telegram.org/bot{token}/sendMessage"
_MAX_MSG_LEN     = 4096
_RATE_LIMIT_SECS = 0.35   # ~3 msgs/sec, safely under Telegram limits

_SEV_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
    "info":     "🔵",
}
_SEV_LABEL = {
    "critical": "CRITICAL",
    "high":     "HIGH",
    "medium":   "MEDIUM",
    "low":      "LOW",
    "info":     "INFO",
}
_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

_DIVIDER      = "━━━━━━━━━━━━━━━━━━━━━━"
_THIN_DIVIDER = "┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄"


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _sev_idx(s: str) -> int:
    return _SEVERITY_ORDER.index(s) if s in _SEVERITY_ORDER else 0


def _trunc(text: str, n: int = 300) -> str:
    return text[:n] + "…" if len(text) > n else text


class TelegramNotifier:
    """Send rich scan alerts to Telegram throughout full scan lifecycle."""

    def __init__(
        self,
        bot_token: str,
        chat_id: str,
        min_severity: str = "high",
    ) -> None:
        self._token       = bot_token
        self._chat_id     = chat_id
        self._min_sev_idx = _sev_idx(min_severity if min_severity in _SEVERITY_ORDER else "high")
        self._url         = _TELEGRAM_API.format(token=bot_token)
        self._scan_start  : Optional[datetime] = None
        # Running counters for final summary
        self._total_cves      = 0
        self._total_vulns     = 0
        self._total_targets   = 0
        self._crit_count      = 0
        self._high_count      = 0
        self._med_count       = 0
        self._low_count       = 0
        self._info_count      = 0

    def _is_alertable(self, severity: str) -> bool:
        return _sev_idx(severity) >= self._min_sev_idx

    # ─────────────────────────────────────────────────────────
    # Core send
    # ─────────────────────────────────────────────────────────

    async def send_message(self, text: str) -> bool:
        if not self._token or not self._chat_id:
            logger.debug("Telegram not configured — skipping")
            return False

        # Escape reserved MarkdownV2 chars NOT inside code blocks
        # We use legacy Markdown (parse_mode=Markdown) — safe enough
        if len(text) > _MAX_MSG_LEN:
            text = text[: _MAX_MSG_LEN - 30] + "\n\n`… (truncated)`"

        payload = {
            "chat_id":                 self._chat_id,
            "text":                    text,
            "parse_mode":              "Markdown",
            "disable_web_page_preview": True,
        }
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self._url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=12),
                ) as resp:
                    if resp.status == 200:
                        return True
                    body = await resp.text()
                    logger.warning("Telegram API %d: %s", resp.status, body[:200])
                    return False
        except Exception as exc:
            logger.warning("Telegram send failed: %s", exc)
            return False

    async def _send(self, text: str) -> None:
        await self.send_message(text)
        await asyncio.sleep(_RATE_LIMIT_SECS)

    # ─────────────────────────────────────────────────────────
    # 1. SCAN STARTED
    # ─────────────────────────────────────────────────────────

    async def alert_scan_started(self, target: str) -> None:
        self._scan_start = datetime.now()
        msg = (
            f"🚀 *GODRECON — SCAN STARTED*\n"
            f"{_DIVIDER}\n"
            f"🎯 *Target:* `{target}`\n"
            f"🕐 *Started:* `{_now()}`\n"
            f"{_DIVIDER}\n"
            f"⚙️ _Subdomain discovery → Tech fingerprint → CVE lookup → Pattern matching_"
        )
        await self._send(msg)

    # ─────────────────────────────────────────────────────────
    # 2. SUBDOMAINS DISCOVERED
    # ─────────────────────────────────────────────────────────

    async def alert_subdomains_found(
        self,
        target: str,
        live_subdomains: List[str],
        total_discovered: int,
        source_stats: Dict[str, int],
        wildcard: bool = False,
    ) -> None:
        live_count  = len(live_subdomains)
        self._total_targets = live_count

        # Top sources by count
        top_sources = sorted(source_stats.items(), key=lambda x: x[1], reverse=True)[:8]
        src_lines   = "\n".join(
            f"  `{name:<20}` {count:>4} subdomains"
            for name, count in top_sources
            if count > 0
        )

        # Preview of live subdomains (first 15)
        preview = live_subdomains[:15]
        sub_lines = "\n".join(f"  • `{s}`" for s in preview)
        more = f"\n  _…and {live_count - 15} more_" if live_count > 15 else ""

        wildcard_note = "\n⚠️ _Wildcard DNS detected — some results may be false positives_" if wildcard else ""

        msg = (
            f"🌐 *SUBDOMAINS DISCOVERED*\n"
            f"{_DIVIDER}\n"
            f"🎯 *Target:* `{target}`\n"
            f"📦 *Total Found:* `{total_discovered}`\n"
            f"✅ *Live (DNS resolved):* `{live_count}`\n"
            f"{wildcard_note}\n"
            f"{_THIN_DIVIDER}\n"
            f"📡 *Top Sources:*\n{src_lines}\n"
            f"{_THIN_DIVIDER}\n"
            f"🔎 *Live Subdomains:*\n{sub_lines}{more}\n"
            f"{_DIVIDER}\n"
            f"⏭ _Starting vulnerability scan on {live_count} targets…_"
        )
        await self._send(msg)

    # ─────────────────────────────────────────────────────────
    # 3. PER-TARGET SCAN STARTED
    # ─────────────────────────────────────────────────────────

    async def alert_target_scan_started(
        self, target: str, index: int, total: int, technologies: List[str]
    ) -> None:
        tech_str = ", ".join(technologies[:10]) if technologies else "unknown"
        msg = (
            f"🔍 *SCANNING TARGET [{index}/{total}]*\n"
            f"{_THIN_DIVIDER}\n"
            f"🎯 `{target}`\n"
            f"🛠 *Tech:* {tech_str}"
        )
        await self._send(msg)

    # ─────────────────────────────────────────────────────────
    # 4. CVE FOUND
    # ─────────────────────────────────────────────────────────

    async def alert_cve_found(
        self, cve: Dict[str, Any], target: str
    ) -> None:
        severity = cve.get("severity", "info")
        if not self._is_alertable(severity):
            return

        self._total_cves += 1
        self._bump_counter(severity)

        cve_id   = cve.get("id", "Unknown")
        tech     = cve.get("technology", "unknown")
        version  = cve.get("detected_version", "")
        cvss     = cve.get("cvss", 0.0)
        summary  = _trunc(cve.get("summary", "No description"), 250)
        source   = cve.get("source", "")
        cwe      = cve.get("cwe", "")
        refs     = cve.get("references", [])
        emoji    = _SEV_EMOJI.get(severity, "⚪")
        label    = _SEV_LABEL.get(severity, severity.upper())
        ver_str  = f" `v{version}`" if version and version != "unknown" else ""

        ref_line = f"\n🔗 *Ref:* {refs[0]}" if refs else ""
        cwe_line = f"\n🏷 *CWE:* `{cwe}`"         if cwe  else ""

        msg = (
            f"{emoji} *CVE — {label}*\n"
            f"{_DIVIDER}\n"
            f"🆔 *CVE ID:* `{cve_id}`\n"
            f"🎯 *Target:* `{target}`\n"
            f"🛠 *Technology:* {tech}{ver_str}\n"
            f"📊 *CVSS:* `{cvss}`\n"
            f"📡 *Source:* {source}"
            f"{cwe_line}"
            f"{ref_line}\n"
            f"{_THIN_DIVIDER}\n"
            f"📝 {summary}"
        )
        await self._send(msg)

    # ─────────────────────────────────────────────────────────
    # 5. VULNERABILITY FOUND (pattern match)
    # ─────────────────────────────────────────────────────────

    async def alert_vuln_found(
        self, match: Dict[str, Any], target: str
    ) -> None:
        severity = match.get("severity", "info")
        if not self._is_alertable(severity):
            return

        self._total_vulns += 1
        self._bump_counter(severity)

        name        = match.get("name", "Unknown")
        url         = match.get("url", target)
        category    = match.get("category", "")
        remediation = _trunc(match.get("remediation", ""), 200)
        confirmed   = match.get("confirmed", False)
        note        = _trunc(match.get("note", ""), 150)
        template_id = match.get("template_id", "")
        emoji       = _SEV_EMOJI.get(severity, "⚪")
        label       = _SEV_LABEL.get(severity, severity.upper())

        status_icon  = "✅ *CONFIRMED*" if confirmed else "⚠️ *POTENTIAL* _(verify manually)_"
        cat_line     = f"\n📂 *Category:* {category}"     if category    else ""
        tmpl_line    = f"\n🏷 *Template:* `{template_id}`" if template_id else ""
        note_line    = f"\n📌 *Note:* {note}"              if note        else ""
        fix_line     = f"\n🛠 *Fix:* {remediation}"        if remediation else ""

        msg = (
            f"{emoji} *VULN — {label}*\n"
            f"{_DIVIDER}\n"
            f"🔍 *Name:* {name}\n"
            f"🎯 *URL:* `{url}`\n"
            f"🔰 *Status:* {status_icon}"
            f"{cat_line}"
            f"{tmpl_line}"
            f"{note_line}"
            f"{fix_line}"
        )
        await self._send(msg)

    # ─────────────────────────────────────────────────────────
    # 6. CVE BULK SUMMARY (per target)
    # ─────────────────────────────────────────────────────────

    async def alert_bulk_cves(
        self, cves: List[Dict[str, Any]], target: str
    ) -> None:
        alertable = [c for c in cves if self._is_alertable(c.get("severity", "info"))]
        if not alertable:
            return

        by_sev: Dict[str, List] = {s: [] for s in _SEVERITY_ORDER}
        for c in alertable:
            by_sev.setdefault(c.get("severity", "info"), []).append(c)

        top = (by_sev["critical"] + by_sev["high"])[:12]
        top_lines = ""
        for c in top:
            e = _SEV_EMOJI.get(c.get("severity", "info"), "⚪")
            top_lines += (
                f"  {e} `{c.get('id','?')}`"
                f" — {c.get('technology','?')} "
                f"_(CVSS {c.get('cvss',0)})_\n"
            )

        msg = (
            f"📋 *CVE SUMMARY — `{target}`*\n"
            f"{_DIVIDER}\n"
            f"🔴 Critical: *{len(by_sev['critical'])}*  "
            f"🟠 High: *{len(by_sev['high'])}*  "
            f"🟡 Medium: *{len(by_sev['medium'])}*\n"
            f"📊 *Total Alertable:* `{len(alertable)}`\n"
            f"{_THIN_DIVIDER}\n"
            f"*Top Critical/High CVEs:*\n{top_lines}"
        )
        await self._send(msg)

    # ─────────────────────────────────────────────────────────
    # 7. PER-TARGET COMPLETE
    # ─────────────────────────────────────────────────────────

    async def alert_target_complete(
        self,
        target: str,
        cve_count: int,
        vuln_count: int,
        index: int,
        total: int,
    ) -> None:
        total_findings = cve_count + vuln_count
        icon = "🚨" if total_findings > 0 else "✅"
        msg = (
            f"{icon} *TARGET DONE [{index}/{total}]*\n"
            f"{_THIN_DIVIDER}\n"
            f"🎯 `{target}`\n"
            f"📊 CVEs: *{cve_count}*  |  Vulns: *{vuln_count}*  |  Total: *{total_findings}*"
        )
        await self._send(msg)

    # ─────────────────────────────────────────────────────────
    # 8. FINAL MASTER SUMMARY
    # ─────────────────────────────────────────────────────────

    async def alert_scan_finished(
        self,
        target: str,
        total_findings: int,
        stats: Dict[str, Any],
    ) -> None:
        duration_secs = stats.get("duration_seconds", 0)
        if duration_secs == 0 and self._scan_start:
            duration_secs = int((datetime.now() - self._scan_start).total_seconds())

        targets_scanned = stats.get("targets_scanned", self._total_targets) or self._total_targets
        total_cves      = stats.get("total_cves",  self._total_cves)
        total_vulns     = stats.get("total_vulns", self._total_vulns)
        posture_score   = stats.get("posture_score", None)
        posture_grade   = stats.get("posture_grade", None)

        # Format duration
        mins, secs = divmod(duration_secs, 60)
        hrs,  mins = divmod(mins, 60)
        if hrs:
            dur_str = f"{hrs}h {mins}m {secs}s"
        elif mins:
            dur_str = f"{mins}m {secs}s"
        else:
            dur_str = f"{secs}s"

        # Risk level
        if self._crit_count > 0:
            risk_icon  = "🆘"
            risk_label = "CRITICAL RISK"
        elif self._high_count > 0:
            risk_icon  = "🚨"
            risk_label = "HIGH RISK"
        elif self._med_count > 0:
            risk_icon  = "⚠️"
            risk_label = "MEDIUM RISK"
        elif self._low_count > 0:
            risk_icon  = "🟢"
            risk_label = "LOW RISK"
        else:
            risk_icon  = "✅"
            risk_label = "CLEAN"

        posture_line = ""
        if posture_score is not None:
            posture_line = f"\n🏅 *Posture Score:* `{posture_score}/100` (Grade *{posture_grade}*)"

        msg = (
            f"🏁 *GODRECON — SCAN COMPLETE*\n"
            f"{_DIVIDER}\n"
            f"🎯 *Target:* `{target}`\n"
            f"🕐 *Finished:* `{_now()}`\n"
            f"⏱ *Duration:* `{dur_str}`\n"
            f"{_DIVIDER}\n"
            f"📡 *Targets Scanned:* `{targets_scanned}`\n"
            f"🐛 *CVEs Found:* `{total_cves}`\n"
            f"🔓 *Vulns Found:* `{total_vulns}`\n"
            f"📊 *Total Findings:* `{total_findings}`"
            f"{posture_line}\n"
            f"{_DIVIDER}\n"
            f"*Severity Breakdown:*\n"
            f"  🔴 Critical: *{self._crit_count}*\n"
            f"  🟠 High:     *{self._high_count}*\n"
            f"  🟡 Medium:   *{self._med_count}*\n"
            f"  🟢 Low:      *{self._low_count}*\n"
            f"  🔵 Info:     *{self._info_count}*\n"
            f"{_DIVIDER}\n"
            f"{risk_icon} *Overall Risk: {risk_label}*"
        )
        await self._send(msg)

    # ─────────────────────────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────────────────────────

    def _bump_counter(self, severity: str) -> None:
        if   severity == "critical": self._crit_count += 1
        elif severity == "high":     self._high_count += 1
        elif severity == "medium":   self._med_count  += 1
        elif severity == "low":      self._low_count  += 1
        else:                        self._info_count += 1


# ─────────────────────────────────────────────────────────
# Shared global notifier — same instance across all modules
# ─────────────────────────────────────────────────────────

_SHARED_NOTIFIER: Optional[TelegramNotifier] = None
_NOTIFIER_CACHE: dict = {}


def get_shared_notifier() -> Optional[TelegramNotifier]:
    """Return the shared global notifier instance."""
    return _SHARED_NOTIFIER


def set_shared_notifier(notifier: TelegramNotifier) -> None:
    """Set the shared global notifier instance."""
    global _SHARED_NOTIFIER
    _SHARED_NOTIFIER = notifier


# ─────────────────────────────────────────────────────────
# Shared global notifier — same instance across all modules
# ─────────────────────────────────────────────────────────

_SHARED_NOTIFIER: Optional[TelegramNotifier] = None


def get_shared_notifier() -> Optional[TelegramNotifier]:
    """Return the shared global notifier instance."""
    return _SHARED_NOTIFIER


def set_shared_notifier(notifier: TelegramNotifier) -> None:
    """Set the shared global notifier instance."""
    global _SHARED_NOTIFIER
    _SHARED_NOTIFIER = notifier


def get_notifier_from_config(config: Any) -> Optional[TelegramNotifier]:
    """Build a TelegramNotifier from scan config if enabled."""
    try:
        tg_cfg = config.notifications.telegram
        if not tg_cfg.enabled:
            return None
        token   = tg_cfg.bot_token
        chat_id = tg_cfg.chat_id
        if not token or not chat_id:
            logger.warning("Telegram enabled but bot_token or chat_id is empty")
            return None
        min_sev = getattr(tg_cfg, "min_severity", "high")
        logger.info("Telegram notifications enabled — chat %s, min_severity=%s", chat_id, min_sev)
        cache_key = f"{token}:{chat_id}"
        if cache_key not in _NOTIFIER_CACHE:
            _NOTIFIER_CACHE[cache_key] = TelegramNotifier(bot_token=token, chat_id=chat_id, min_severity=min_sev)
        return _NOTIFIER_CACHE[cache_key]
    except Exception as exc:
        logger.debug("Could not init Telegram notifier: %s", exc)
        return None
