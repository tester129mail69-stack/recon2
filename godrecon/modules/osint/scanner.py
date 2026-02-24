"""OSINT module entry point for GODRECON.

Orchestrates WHOIS lookup, social media discovery, and Google dork generation
concurrently, then aggregates findings into a single :class:`ModuleResult`.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult
from godrecon.modules.osint.google_dorks import GoogleDorkScanner
from godrecon.modules.osint.social import SocialMediaScanner
from godrecon.modules.osint.whois_lookup import WHOISLookup
from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)


class OSINTModule(BaseModule):
    """OSINT intelligence: WHOIS, social media, Google dorks, metadata."""

    name = "osint"
    description = "OSINT intelligence: WHOIS, social media, Google dorks, metadata"
    author = "GODRECON Team"
    version = "1.0.0"
    category = "osint"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        """Run all OSINT sub-checks for *target*.

        Args:
            target: Domain name to investigate.
            config: Scan configuration.

        Returns:
            :class:`ModuleResult` with all OSINT findings.
        """
        result = ModuleResult(module_name=self.name, target=target)

        async with AsyncHTTPClient(
            timeout=config.general.timeout,
            user_agents=config.general.user_agents,
            proxy=config.general.proxy,
            verify_ssl=False,
            retries=1,
        ) as http:
            whois_task = asyncio.create_task(WHOISLookup(http).lookup(target))
            social_task = asyncio.create_task(SocialMediaScanner(http).scan(target))
            dork_scanner = GoogleDorkScanner()
            dork_task = asyncio.create_task(dork_scanner.generate_dorks(target))

            whois_data, social_profiles, dorks = await asyncio.gather(
                whois_task, social_task, dork_task, return_exceptions=True
            )

        # --- WHOIS findings ---
        if isinstance(whois_data, dict):
            self._add_whois_findings(result, whois_data, target)
            result.raw["whois"] = whois_data
        else:
            logger.warning("WHOIS lookup failed: %s", whois_data)

        # --- Social media findings ---
        if isinstance(social_profiles, list):
            self._add_social_findings(result, social_profiles)
            result.raw["social"] = social_profiles
        else:
            logger.warning("Social scan failed: %s", social_profiles)

        # --- Google dork findings ---
        if isinstance(dorks, list):
            result.raw["google_dorks"] = dorks
            result.findings.append(
                Finding(
                    title=f"Google Dorks Generated ({len(dorks)} queries)",
                    description=(
                        f"Generated {len(dorks)} Google dork queries for {target}. "
                        "Review these manually to identify information leaks."
                    ),
                    severity="info",
                    data={"count": len(dorks), "dorks": dorks[:10]},
                    tags=["osint", "google-dorks"],
                )
            )
        else:
            logger.warning("Dork generation failed: %s", dorks)

        logger.info(
            "OSINT for %s complete — %d findings", target, len(result.findings)
        )
        return result

    @staticmethod
    def _add_whois_findings(
        result: ModuleResult, whois: Dict[str, Any], target: str
    ) -> None:
        """Create findings from a WHOIS result dict.

        Args:
            result: ModuleResult to append findings to.
            whois: Parsed WHOIS/RDAP data.
            target: Domain being scanned.
        """
        description_parts = []
        if whois.get("registrar"):
            description_parts.append(f"Registrar: {whois['registrar']}")
        if whois.get("creation_date"):
            description_parts.append(f"Created: {whois['creation_date']}")
        if whois.get("expiry_date"):
            description_parts.append(f"Expires: {whois['expiry_date']}")
        if whois.get("registrant_org"):
            description_parts.append(f"Registrant org: {whois['registrant_org']}")
        if whois.get("domain_age_days") is not None:
            description_parts.append(f"Domain age: {whois['domain_age_days']} days")

        result.findings.append(
            Finding(
                title=f"WHOIS Information for {target}",
                description="\n".join(description_parts) or "WHOIS data retrieved.",
                severity="info",
                data=whois,
                tags=["osint", "whois"],
            )
        )

        # Suspicious newly-registered domain
        if whois.get("suspicious_age"):
            result.findings.append(
                Finding(
                    title=f"Newly Registered Domain: {target}",
                    description=(
                        f"Domain {target} was registered only "
                        f"{whois.get('domain_age_days', 'an unknown number of')} days ago. "
                        "Newly registered domains are associated with phishing campaigns."
                    ),
                    severity="medium",
                    data=whois,
                    tags=["osint", "whois", "suspicious"],
                )
            )

        # Missing privacy protection
        if not whois.get("privacy_protected") and whois.get("registrant_email"):
            result.findings.append(
                Finding(
                    title=f"No WHOIS Privacy Protection on {target}",
                    description=(
                        "The domain does not use a WHOIS privacy service. "
                        f"Registrant email {whois['registrant_email']!r} is publicly visible."
                    ),
                    severity="low",
                    data={"registrant_email": whois.get("registrant_email")},
                    tags=["osint", "whois", "privacy"],
                )
            )

    @staticmethod
    def _add_social_findings(
        result: ModuleResult, profiles: List[Dict[str, Any]]
    ) -> None:
        """Create findings from social media scan results.

        Args:
            result: ModuleResult to append findings to.
            profiles: List of social profile check dicts.
        """
        found = [p for p in profiles if p.get("found")]
        if found:
            platforms_str = ", ".join(p["platform"] for p in found)
            result.findings.append(
                Finding(
                    title=f"Social Media Profiles Found ({len(found)})",
                    description=(
                        f"Found potential social media presence on: {platforms_str}."
                    ),
                    severity="info",
                    data={"profiles": found},
                    tags=["osint", "social-media"],
                )
            )
