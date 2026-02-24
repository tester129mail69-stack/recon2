"""Web crawl module entry point for GODRECON.

Orchestrates the web spider, form extraction, and JavaScript analysis.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult
from godrecon.modules.crawl.forms import FormFinder
from godrecon.modules.crawl.js_analyzer import JSAnalyzer
from godrecon.modules.crawl.spider import WebSpider
from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)


class WebCrawlModule(BaseModule):
    """Web crawling: spider, form extraction, JS analysis."""

    name = "crawl"
    description = "Web crawling: spider, form extraction, JS analysis"
    author = "GODRECON Team"
    version = "1.0.0"
    category = "crawl"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        """Run web crawl and analysis for *target*.

        Args:
            target: Domain name or URL to crawl.
            config: Scan configuration.

        Returns:
            :class:`ModuleResult` with crawl findings.
        """
        result = ModuleResult(module_name=self.name, target=target)
        crawl_cfg = getattr(config, "crawl", None)
        max_depth = getattr(crawl_cfg, "max_depth", 3)
        max_pages = getattr(crawl_cfg, "max_pages", 100)
        respect_robots = getattr(crawl_cfg, "respect_robots", True)

        start_url = f"https://{target}" if not target.startswith("http") else target

        async with AsyncHTTPClient(
            timeout=config.general.timeout,
            user_agents=config.general.user_agents,
            proxy=config.general.proxy,
            verify_ssl=False,
            retries=1,
        ) as http:
            # Phase 1: Spider
            spider = WebSpider(http)
            crawl_data: Dict[str, Any] = {}
            try:
                crawl_data = await spider.crawl(
                    start_url,
                    max_depth=max_depth,
                    max_pages=max_pages,
                    respect_robots=respect_robots,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Spider failed for %s: %s", target, exc)
                crawl_data = {"pages": [], "forms": [], "scripts": [], "links": [], "comments": []}

            pages = crawl_data.get("pages", [])
            forms = crawl_data.get("forms", [])
            scripts = crawl_data.get("scripts", [])
            comments = crawl_data.get("comments", [])

            # Phase 2: JS analysis (concurrent)
            js_analyzer = JSAnalyzer()
            js_tasks = [
                asyncio.create_task(js_analyzer.analyze(js_url, http))
                for js_url in scripts[:20]  # cap at 20 JS files
            ]
            js_results_raw = await asyncio.gather(*js_tasks, return_exceptions=True)

            # Phase 3: Form analysis from already-collected forms
            form_finder = FormFinder()
            all_forms: List[Dict[str, Any]] = list(forms)
            # Re-extract forms from crawled pages for more detail
            for page in pages[:50]:
                page_forms = form_finder.extract_forms(
                    page.get("body", ""), page.get("url", "")
                )
                all_forms.extend(page_forms)

        result.raw = {
            "pages_crawled": len(pages),
            "scripts_found": len(scripts),
            "forms_found": len(all_forms),
            "comments": comments[:20],
        }

        # Findings: pages summary
        if pages:
            result.findings.append(
                Finding(
                    title=f"Web Crawl Complete: {len(pages)} Pages",
                    description=(
                        f"Crawled {len(pages)} pages, found {len(scripts)} JS files, "
                        f"{len(all_forms)} forms, and {len(comments)} HTML comments."
                    ),
                    severity="info",
                    data={"pages": len(pages), "scripts": len(scripts), "forms": len(all_forms)},
                    tags=["crawl", "spider"],
                )
            )

        # Findings: forms without CSRF
        missing_csrf_forms = [f for f in all_forms if f.get("missing_csrf")]
        if missing_csrf_forms:
            result.findings.append(
                Finding(
                    title=f"Forms Missing CSRF Protection ({len(missing_csrf_forms)})",
                    description=(
                        f"{len(missing_csrf_forms)} POST form(s) lack a CSRF token. "
                        "This may allow cross-site request forgery attacks."
                    ),
                    severity="medium",
                    data={"forms": [
                        {"action": f["action"], "method": f["method"]}
                        for f in missing_csrf_forms[:10]
                    ]},
                    tags=["crawl", "csrf", "form"],
                )
            )

        # Findings: JS secrets
        for js_result in js_results_raw:
            if not isinstance(js_result, list):
                continue
            for secret in js_result:
                result.findings.append(
                    Finding(
                        title=f"Secret Found in JS: {secret.get('pattern_name', 'Unknown')}",
                        description=(
                            f"{secret.get('description', '')} "
                            f"(line {secret.get('line', '?')}, URL: {secret.get('url', '')})"
                        ),
                        severity=secret.get("severity", "high"),
                        data=secret,
                        tags=["crawl", "js", "secret", secret.get("severity", "")],
                    )
                )

        # Findings: interesting HTML comments
        sensitive_comments = [
            c for c in comments
            if any(kw in c.lower() for kw in ("todo", "fixme", "password", "key", "secret", "hack", "debug"))
        ]
        if sensitive_comments:
            result.findings.append(
                Finding(
                    title=f"Sensitive HTML Comments Found ({len(sensitive_comments)})",
                    description="HTML comments may contain developer notes or sensitive data.",
                    severity="low",
                    data={"comments": sensitive_comments[:5]},
                    tags=["crawl", "comment"],
                )
            )

        logger.info(
            "Crawl for %s complete — %d findings", target, len(result.findings)
        )
        return result
