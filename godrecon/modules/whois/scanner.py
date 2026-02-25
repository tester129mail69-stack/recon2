"""WHOIS domain registration lookup module for GODRECON."""

from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List, Optional

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_TLD_SERVERS: Dict[str, str] = {
    ".com": "whois.verisign-grs.net",
    ".org": "whois.pir.org",
    ".net": "whois.verisign-grs.net",
}
_DEFAULT_SERVER = "whois.iana.org"


class WHOISModule(BaseModule):
    """WHOIS domain registration lookup."""

    name = "whois"
    description = "WHOIS domain registration lookup"
    author = "GODRECON Team"
    version = "1.0.0"
    category = "osint"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=target)

        try:
            # Extract root domain (strip scheme/path/port)
            domain = re.sub(r"https?://", "", target).split("/")[0].split(":")[0].strip()

            # Determine TLD and WHOIS server
            tld = "." + domain.rsplit(".", 1)[-1] if "." in domain else ""
            server = _TLD_SERVERS.get(tld, _DEFAULT_SERVER)

            raw_text = await self._whois_query(domain, server)
            parsed = self._parse_whois(raw_text)

            finding_data: Dict[str, Any] = {"raw": raw_text, **parsed}
            result.raw = finding_data

            name_servers: List[str] = parsed.get("name_servers", [])
            status: List[str] = parsed.get("status", [])

            result.findings.append(
                Finding(
                    title=f"WHOIS Record: {domain}",
                    description=(
                        f"Registrar: {parsed.get('registrar', 'N/A')}\n"
                        f"Created: {parsed.get('creation_date', 'N/A')}\n"
                        f"Expires: {parsed.get('expiry_date', 'N/A')}\n"
                        f"Updated: {parsed.get('updated_date', 'N/A')}\n"
                        f"Registrant Org: {parsed.get('registrant_org', 'N/A')}\n"
                        f"Name Servers: {', '.join(name_servers)}\n"
                        f"Status: {', '.join(status)}"
                    ),
                    severity="info",
                    data=finding_data,
                    tags=["whois", "osint", "registration"],
                )
            )

            logger.info("WHOIS lookup for %s complete", domain)
        except Exception as exc:  # noqa: BLE001
            logger.error("WHOIS module error for %s: %s", target, exc)

        return result

    async def _whois_query(self, domain: str, server: str) -> str:
        """Connect to *server*:43 and query *domain*, returning raw response text."""
        async def _connect() -> str:
            reader, writer = await asyncio.open_connection(server, 43)
            try:
                writer.write(f"{domain}\r\n".encode())
                await writer.drain()
                data = await reader.read(65536)
                return data.decode(errors="replace")
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:  # noqa: BLE001
                    pass

        return await asyncio.wait_for(_connect(), timeout=10)

    @staticmethod
    def _parse_whois(raw_text: str) -> Dict[str, Any]:
        """Parse common WHOIS fields from *raw_text*."""
        result: Dict[str, Any] = {
            "domain_name": None,
            "registrar": None,
            "creation_date": None,
            "expiry_date": None,
            "updated_date": None,
            "name_servers": [],
            "status": [],
            "registrant_org": None,
        }

        patterns = {
            "domain_name": re.compile(r"^Domain Name:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
            "registrar": re.compile(r"^Registrar:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
            "creation_date": re.compile(r"^Creation Date:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
            "expiry_date": re.compile(r"^Registry Expiry Date:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
            "updated_date": re.compile(r"^Updated Date:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
            "registrant_org": re.compile(r"^Registrant Organi[sz]ation:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
        }

        for field, pattern in patterns.items():
            match = pattern.search(raw_text)
            if match:
                result[field] = match.group(1).strip()

        result["name_servers"] = [
            m.group(1).strip()
            for m in re.finditer(r"^Name Server:\s*(.+)$", raw_text, re.IGNORECASE | re.MULTILINE)
        ]
        result["status"] = [
            m.group(1).strip()
            for m in re.finditer(r"^Domain Status:\s*(.+)$", raw_text, re.IGNORECASE | re.MULTILINE)
        ]

        return result

    @staticmethod
    async def _run_safe(name: str, coro: Any) -> Any:
        try:
            return await coro
        except Exception as exc:  # noqa: BLE001
            logger.warning("Sub-check '%s' failed: %s", name, exc)
            return None
