"""Cloud security module entry point for GODRECON.

Orchestrates AWS S3, Azure Blob, and GCP Storage bucket enumeration.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult
from godrecon.modules.cloud.aws import AWSDetector
from godrecon.modules.cloud.azure import AzureDetector
from godrecon.modules.cloud.gcp import GCPDetector
from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)


class CloudSecurityModule(BaseModule):
    """Cloud asset enumeration: AWS S3, Azure Blob, GCP Storage."""

    name = "cloud"
    description = "Cloud asset enumeration: AWS S3, Azure Blob, GCP Storage"
    author = "GODRECON Team"
    version = "1.0.0"
    category = "cloud"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        """Run cloud asset checks for *target*.

        Args:
            target: Domain name to investigate.
            config: Scan configuration.

        Returns:
            :class:`ModuleResult` with cloud findings.
        """
        result = ModuleResult(module_name=self.name, target=target)
        max_patterns = getattr(
            getattr(config, "cloud_config", None), "bucket_permutations", 10
        )

        async with AsyncHTTPClient(
            timeout=config.general.timeout,
            user_agents=config.general.user_agents,
            proxy=config.general.proxy,
            verify_ssl=False,
            retries=0,
        ) as http:
            aws_task = asyncio.create_task(
                AWSDetector().detect(target, http, max_patterns=max_patterns)
            )
            azure_task = asyncio.create_task(
                AzureDetector().detect(target, http, max_patterns=max_patterns)
            )
            gcp_task = asyncio.create_task(
                GCPDetector().detect(target, http, max_patterns=max_patterns)
            )
            aws_findings, azure_findings, gcp_findings = await asyncio.gather(
                aws_task, azure_task, gcp_task, return_exceptions=True
            )

        all_raw: Dict[str, Any] = {}
        for provider, provider_findings in [
            ("aws", aws_findings),
            ("azure", azure_findings),
            ("gcp", gcp_findings),
        ]:
            if isinstance(provider_findings, list):
                all_raw[provider] = provider_findings
                for item in provider_findings:
                    self._add_cloud_finding(result, item, provider)
            else:
                logger.warning("Cloud %s check failed: %s", provider, provider_findings)
                all_raw[provider] = []

        result.raw = all_raw
        logger.info(
            "Cloud scan for %s complete — %d findings", target, len(result.findings)
        )
        return result

    @staticmethod
    def _add_cloud_finding(
        result: ModuleResult, item: Dict[str, Any], provider: str
    ) -> None:
        """Convert a raw cloud detection dict into a Finding.

        Args:
            result: ModuleResult to append to.
            item: Raw detection dict from a cloud detector.
            provider: Provider label (aws/azure/gcp).
        """
        severity = item.get("severity", "info")
        title_map = {
            "aws_s3_public": "Public S3 Bucket Exposed",
            "aws_s3_exists": "S3 Bucket Exists (Access Denied)",
            "aws_cloudfront": "AWS CloudFront Distribution Detected",
            "aws_hosted": "Target Hosted on AWS",
            "azure_blob_public": "Public Azure Blob Storage Exposed",
            "azure_blob_exists": "Azure Blob Storage Exists (Access Denied)",
            "azure_app_service": "Azure App Service Exposed",
            "azure_app_service_exists": "Azure App Service Exists",
            "gcp_storage_public": "Public GCP Storage Bucket Exposed",
            "gcp_storage_exists": "GCP Storage Bucket Exists (Access Denied)",
            "firebase_public": "Public Firebase Database Exposed",
            "firebase_exists": "Firebase Database Exists (Access Denied)",
        }
        finding_type = item.get("type", "cloud_asset")
        title = title_map.get(finding_type, f"Cloud Asset Detected ({finding_type})")
        result.findings.append(
            Finding(
                title=title,
                description=item.get("description", ""),
                severity=severity,
                data=item,
                tags=["cloud", provider, finding_type],
            )
        )
