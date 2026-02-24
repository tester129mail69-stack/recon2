"""Content discovery scanner module for GODRECON.

Auto-discovered by the scan engine via the ``scanner`` sub-module convention.
Runs directory brute-forcing, sensitive file detection, and backup file
enumeration against each live HTTP/HTTPS service on the target.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult
from godrecon.modules.http.content_discovery import ContentDiscovery
from godrecon.modules.http.sensitive_files import SensitiveFileChecker
from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# Sensitive path / file keywords that warrant CRITICAL severity.
_CRITICAL_KEYWORDS = {
    ".env", ".git/config", "private", "id_rsa", "id_dsa", "id_ecdsa",
    "id_ed25519", ".aws/credentials", ".npmrc", "composer.json",
}


class ContentDiscoveryModule(BaseModule):
    """Directory brute-forcing, sensitive file detection, and backup discovery.

    For each candidate base URL (HTTP and HTTPS) the module:

    1. Runs wordlist-based directory discovery with wildcard detection.
    2. Checks a comprehensive list of sensitive paths.
    3. Probes backup variants of every discovered file.
    """

    name = "content_discovery"
    description = "Directory brute-forcing, sensitive file detection, and backup file discovery"
    author = "GODRECON Team"
    version = "1.0.0"
    category = "http"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        """Run content discovery against *target*.

        Args:
            target: Domain or IP address to scan.
            config: Global scan configuration.

        Returns:
            :class:`ModuleResult` with all content-discovery findings.
        """
        result = ModuleResult(module_name=self.name, target=target)

        # Pull optional content_discovery config block, fall back to defaults.
        cd_cfg = getattr(config, "content_discovery", None)
        timeout: float = float(getattr(cd_cfg, "timeout", 10.0))
        concurrency: int = int(getattr(cd_cfg, "concurrency", 50))
        wordlist_path = getattr(cd_cfg, "wordlist", None)
        status_codes = getattr(cd_cfg, "status_codes", None)
        recursive: bool = bool(getattr(cd_cfg, "recursive", False))
        max_depth: int = int(getattr(cd_cfg, "recursive_depth", 2))

        base_urls = [f"http://{target}", f"https://{target}"]

        all_discovered: List[Dict[str, Any]] = []
        all_sensitive: List[Dict[str, Any]] = []
        all_backups: List[Dict[str, Any]] = []

        async with AsyncHTTPClient(
            timeout=int(timeout),
            max_connections=concurrency,
            verify_ssl=False,
            retries=1,
        ) as http:
            for base_url in base_urls:
                disc = ContentDiscovery(
                    http_client=http,
                    concurrency=concurrency,
                    timeout=timeout,
                    status_codes=status_codes,
                    wordlist_path=wordlist_path,
                )
                checker = SensitiveFileChecker(
                    http_client=http,
                    timeout=timeout,
                    concurrency=30,
                )

                try:
                    discovered, sensitive = await asyncio.gather(
                        disc.run(base_url, recursive=recursive, max_depth=max_depth),
                        checker.check(base_url),
                        return_exceptions=True,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Content discovery error on %s: %s", base_url, exc)
                    continue

                if isinstance(discovered, Exception):
                    logger.warning("Directory brute-force error on %s: %s", base_url, discovered)
                    discovered = []
                if isinstance(sensitive, Exception):
                    logger.warning("Sensitive-file check error on %s: %s", base_url, sensitive)
                    sensitive = []

                all_discovered.extend(discovered)  # type: ignore[arg-type]
                all_sensitive.extend(sensitive)  # type: ignore[arg-type]

                # Backup probing for every discovered path.
                backup_tasks = [
                    asyncio.create_task(disc.check_backups(entry["url"]))
                    for entry in discovered  # type: ignore[union-attr]
                ]
                if backup_tasks:
                    backup_results = await asyncio.gather(*backup_tasks, return_exceptions=True)
                    for br in backup_results:
                        if isinstance(br, list):
                            all_backups.extend(br)

        # ------------------------------------------------------------------
        # Build findings
        # ------------------------------------------------------------------
        self._add_sensitive_findings(result, all_sensitive)
        self._add_backup_findings(result, all_backups)
        self._add_discovery_findings(result, all_discovered)

        result.raw = {
            "discovered_paths": all_discovered,
            "sensitive_files": all_sensitive,
            "backup_files": all_backups,
        }

        logger.info(
            "Content discovery for %s complete — %d paths, %d sensitive, %d backups, %d findings",
            target,
            len(all_discovered),
            len(all_sensitive),
            len(all_backups),
            len(result.findings),
        )
        return result

    # ------------------------------------------------------------------
    # Finding builders
    # ------------------------------------------------------------------

    @staticmethod
    def _add_sensitive_findings(
        result: ModuleResult,
        sensitive: List[Dict[str, Any]],
    ) -> None:
        """Translate sensitive-file hits into :class:`Finding` objects."""
        for entry in sensitive:
            path: str = entry.get("path", "")
            raw_severity: str = entry.get("severity", "info")
            category: str = entry.get("category", "")
            url: str = entry.get("url", "")

            # Escalate to CRITICAL for highly sensitive paths.
            severity = raw_severity
            if any(kw in path.lower() for kw in _CRITICAL_KEYWORDS):
                severity = "critical"
            elif raw_severity == "critical":
                severity = "critical"
            elif raw_severity == "high":
                severity = "high"
            elif category == "admin":
                severity = "medium"

            result.findings.append(
                Finding(
                    title=f"Sensitive File Exposed: {path}",
                    description=(
                        f"{entry.get('description', '')} — "
                        f"HTTP {entry.get('status_code')} at {url}"
                    ),
                    severity=severity,
                    data=entry,
                    tags=["http", "sensitive-file", category],
                )
            )

    @staticmethod
    def _add_backup_findings(
        result: ModuleResult,
        backups: List[Dict[str, Any]],
    ) -> None:
        """Translate backup-file hits into :class:`Finding` objects."""
        for entry in backups:
            result.findings.append(
                Finding(
                    title=f"Backup File Exposed: {entry.get('path', '')}",
                    description=(
                        f"Backup variant of a web resource is publicly accessible "
                        f"(HTTP {entry.get('status_code')}) at {entry.get('url', '')}."
                    ),
                    severity="high",
                    data=entry,
                    tags=["http", "backup-file", "content-discovery"],
                )
            )

    @staticmethod
    def _add_discovery_findings(
        result: ModuleResult,
        discovered: List[Dict[str, Any]],
    ) -> None:
        """Translate brute-force hits into informational :class:`Finding` objects."""
        for entry in discovered:
            result.findings.append(
                Finding(
                    title=f"Directory/Path Discovered: {entry.get('path', '')}",
                    description=(
                        f"HTTP {entry.get('status_code')} — "
                        f"{entry.get('url', '')} "
                        f"(content-length: {entry.get('content_length', 'unknown')})"
                    ),
                    severity="info",
                    data=entry,
                    tags=["http", "content-discovery", "directory"],
                )
            )
