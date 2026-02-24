"""Visual reconnaissance orchestrator for GODRECON.

Runs screenshot capture followed by visual similarity analysis and
page-type classification.  Auto-discovered by the scan engine via the
``visual`` package ``__init__.py`` export.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult
from godrecon.modules.visual.screenshot import ScreenshotCapture, ScreenshotResult
from godrecon.modules.visual.similarity import VisualSimilarityAnalyzer
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)


class VisualReconModule(BaseModule):
    """Visual reconnaissance: screenshots, similarity analysis, page classification.

    Captures screenshots for all live HTTP hosts discovered by the HTTP probe
    module, groups visually similar pages, and classifies each page type
    (login, admin panel, default server page, error page).
    """

    name = "visual"
    description = (
        "Visual reconnaissance: headless-browser screenshots, perceptual-hash "
        "similarity grouping, and page-type classification (login, admin, default, error)"
    )
    author = "GODRECON Team"
    version = "1.0.0"
    category = "visual"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        """Run visual recon for *target*.

        Args:
            target: Primary scan target (domain name).
            config: Global scan configuration.

        Returns:
            :class:`ModuleResult` with visual intelligence findings.
        """
        result = ModuleResult(module_name=self.name, target=target)
        vis_cfg = getattr(config, "visual", None)

        screenshots_enabled = getattr(vis_cfg, "screenshots", True)
        similarity_enabled = getattr(vis_cfg, "similarity", True)
        concurrency = getattr(vis_cfg, "concurrency", 5)
        timeout = getattr(vis_cfg, "timeout", 15)
        viewport_w = getattr(vis_cfg, "viewport_width", 1280)
        viewport_h = getattr(vis_cfg, "viewport_height", 720)
        output_dir = getattr(vis_cfg, "output_dir", "output/screenshots")

        # Build URL list from HTTP probe results stored in the engine or
        # fall back to constructing URLs from the target domain.
        urls = self._build_url_list(target)

        if not screenshots_enabled:
            logger.info("Screenshots disabled — skipping visual recon for %s", target)
            result.raw = {"screenshots": [], "groups": [], "classifications": []}
            return result

        capturer = ScreenshotCapture(
            output_dir=output_dir,
            concurrency=concurrency,
            timeout=timeout,
            viewport_width=viewport_w,
            viewport_height=viewport_h,
        )

        logger.info("Capturing screenshots for %d URLs (target=%s)", len(urls), target)
        screenshot_results: List[ScreenshotResult] = await capturer.capture_all(urls)

        analyzer = VisualSimilarityAnalyzer()

        # Classify each page and build findings
        classifications = []
        screenshot_paths: Dict[str, str] = {}
        for sr in screenshot_results:
            cls = analyzer.classify_page(
                url=sr.url,
                html_content=None,  # HTML not re-fetched here; use metadata
                screenshot_path=sr.screenshot_path,
            )
            classifications.append(cls)
            self._add_screenshot_findings(result, sr, cls)
            if sr.screenshot_path:
                screenshot_paths[sr.url] = sr.screenshot_path

        # Visual similarity grouping
        groups = []
        if similarity_enabled and screenshot_paths:
            groups = analyzer.group_similar(screenshot_paths)
            for grp in groups:
                if len(grp.members) > 1:
                    result.findings.append(
                        Finding(
                            title=f"Visually Similar Pages Group ({len(grp.members)} pages)",
                            description=(
                                f"{len(grp.members)} pages appear visually identical "
                                f"(perceptual hash: {grp.hash_value}). "
                                f"Representative: {grp.representative_url}"
                            ),
                            severity="info",
                            data=grp.to_dict(),
                            tags=["visual", "similarity"],
                        )
                    )

        result.raw = {
            "screenshots": [sr.to_dict() for sr in screenshot_results],
            "classifications": [cls.to_dict() for cls in classifications],
            "groups": [g.to_dict() for g in groups],
        }

        logger.info(
            "Visual recon for %s complete — %d findings, %d screenshots",
            target,
            len(result.findings),
            len(screenshot_results),
        )
        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_url_list(target: str) -> List[str]:
        """Build initial URL list for a domain target.

        Args:
            target: Domain name or IP address.

        Returns:
            List of URL strings to capture.
        """
        urls = []
        for scheme in ("https", "http"):
            urls.append(f"{scheme}://{target}")
        return urls

    @staticmethod
    def _add_screenshot_findings(
        result: ModuleResult,
        sr: ScreenshotResult,
        cls: Any,
    ) -> None:
        """Add findings derived from a single screenshot result.

        Args:
            result: Module result to append findings to.
            sr: Screenshot capture result.
            cls: Page classification result.
        """
        if sr.error:
            result.findings.append(
                Finding(
                    title=f"Screenshot Failed: {sr.original_url}",
                    description=f"Could not capture screenshot: {sr.error}",
                    severity="info",
                    data=sr.to_dict(),
                    tags=["visual", "screenshot", "error"],
                )
            )
            return

        # JavaScript errors on the page
        if sr.js_errors:
            result.findings.append(
                Finding(
                    title=f"JavaScript Errors Detected: {sr.url}",
                    description=(
                        f"{len(sr.js_errors)} JavaScript error(s) detected on {sr.url}.\n"
                        + "\n".join(sr.js_errors[:5])
                    ),
                    severity="info",
                    data={"js_errors": sr.js_errors, "url": sr.url},
                    tags=["visual", "javascript", "errors"],
                )
            )

        # Page-type specific findings
        page_type = cls.page_type
        severity = cls.severity

        type_titles = {
            "login": f"Login Page Detected: {sr.url}",
            "admin": f"Admin Panel Detected: {sr.url}",
            "default": f"Default Server Page Detected: {sr.url}",
            "error": f"Error Page Detected: {sr.url}",
        }
        type_descriptions = {
            "login": f"A login/authentication page was detected at {sr.url}.",
            "admin": (
                f"An administrative panel or management interface was detected at {sr.url}. "
                "This may expose privileged functionality."
            ),
            "default": (
                f"The target at {sr.url} is serving a default server page "
                "(e.g. Apache/Nginx/IIS default). This may indicate an unconfigured service."
            ),
            "error": f"An error page was detected at {sr.url}.",
        }

        if page_type in type_titles:
            result.findings.append(
                Finding(
                    title=type_titles[page_type],
                    description=type_descriptions[page_type],
                    severity=severity,
                    data={
                        **sr.to_dict(),
                        "page_type": page_type,
                        "patterns_matched": cls.patterns_matched,
                    },
                    tags=["visual", page_type],
                )
            )
        else:
            # Generic "screenshot captured" finding
            result.findings.append(
                Finding(
                    title=f"Screenshot Captured: {sr.url}",
                    description=(
                        f"Screenshot captured for {sr.url}. "
                        f"Title: {sr.title!r}. Status: {sr.status_code}."
                    ),
                    severity="info",
                    data=sr.to_dict(),
                    tags=["visual", "screenshot"],
                )
            )
