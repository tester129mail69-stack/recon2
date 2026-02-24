"""Configuration management for GODRECON.

Loads configuration from config.yaml, with support for CLI overrides
and environment variables.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field


class DNSConfig(BaseModel):
    """DNS resolver configuration."""

    resolvers: List[str] = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]
    timeout: int = 5


class SubdomainBruteforceConfig(BaseModel):
    """Brute-force configuration for subdomain enumeration."""

    enabled: bool = True
    wordlist: str = "wordlists/subdomains-medium.txt"
    concurrency: int = 500


class SubdomainPermutationConfig(BaseModel):
    """Permutation scanner configuration."""

    enabled: bool = True


class SubdomainRecursiveConfig(BaseModel):
    """Recursive enumeration configuration."""

    enabled: bool = False
    depth: int = 2


class SubdomainModuleConfig(BaseModel):
    """Detailed configuration for the subdomain enumeration module."""

    enabled: bool = True
    sources: List[str] = Field(default_factory=lambda: ["all"])
    bruteforce: SubdomainBruteforceConfig = Field(
        default_factory=SubdomainBruteforceConfig
    )
    permutation: SubdomainPermutationConfig = Field(
        default_factory=SubdomainPermutationConfig
    )
    recursive: SubdomainRecursiveConfig = Field(
        default_factory=SubdomainRecursiveConfig
    )
    timeout_per_source: int = 30


class DNSModuleConfig(BaseModel):
    """Configuration for the DNS intelligence module."""

    enabled: bool = True
    resolve_all_types: bool = True
    check_dnssec: bool = True
    attempt_zone_transfer: bool = True
    check_security: bool = True
    email_security: bool = True
    passive_dns: bool = True
    dkim_selectors: List[str] = Field(
        default_factory=lambda: [
            "default", "google", "selector1", "selector2", "k1", "k2",
            "dkim", "mail", "email", "s1", "s2", "mandrill", "amazonses",
            "cm", "protonmail", "zoho",
        ]
    )
    doh_enabled: bool = False
    doh_server: str = "https://cloudflare-dns.com/dns-query"


class ModulesConfig(BaseModel):
    """Enable/disable individual scan modules."""

    subdomains: bool = True
    dns: bool = True
    http_probe: bool = True
    ports: bool = False
    tech: bool = True
    osint: bool = True
    takeover: bool = True
    cloud: bool = True
    vulns: bool = True
    crawl: bool = False
    ssl: bool = True
    email_sec: bool = True
    screenshots: bool = False
    api_intel: bool = True
    content_discovery: bool = True


class HttpProbeConfig(BaseModel):
    """HTTP probing configuration."""

    enabled: bool = True
    ports: List[int] = Field(default_factory=lambda: [80, 443, 8080, 8443, 8000, 8888, 3000, 5000])
    concurrency: int = 100
    timeout: int = 10
    follow_redirects: bool = True
    max_redirects: int = 5
    check_security_headers: bool = True
    check_cors: bool = True


class TechDetectionConfig(BaseModel):
    """Technology detection configuration."""

    enabled: bool = True
    detect_cms: bool = True
    detect_waf: bool = True
    detect_cdn: bool = True
    detect_frameworks: bool = True
    favicon_hash: bool = True
    jarm: bool = True


class SSLAnalysisConfig(BaseModel):
    """SSL/TLS analysis configuration."""

    enabled: bool = True
    check_ciphers: bool = True
    check_vulnerabilities: bool = True
    check_certificate: bool = True
    check_protocols: bool = True
    grade: bool = True


class PortScanConfig(BaseModel):
    """Port scanning configuration."""

    enabled: bool = True
    scan_type: str = "top100"  # top100, top1000, custom, full
    custom_ports: List[int] = Field(default_factory=list)
    concurrency: int = 500
    timeout: float = 3.0
    banner_grab: bool = True
    service_detection: bool = True


class ContentDiscoveryConfig(BaseModel):
    """Content and directory discovery configuration."""

    enabled: bool = True
    wordlist: str = "wordlists/directories.txt"
    concurrency: int = 50
    status_codes: List[int] = Field(default_factory=lambda: [200, 201, 301, 302, 307, 401, 403])
    recursive: bool = False
    recursive_depth: int = 2
    check_sensitive_files: bool = True
    check_backups: bool = True
    timeout: float = 10.0


class TakeoverConfig(BaseModel):
    """Subdomain takeover detection configuration."""

    enabled: bool = True
    verify: bool = True
    check_all_subdomains: bool = True


class APIKeysConfig(BaseModel):
    """API key configuration for external services."""

    shodan: str = ""
    censys_id: str = ""
    censys_secret: str = ""
    virustotal: str = ""
    securitytrails: str = ""
    binaryedge: str = ""
    hunter: str = ""
    github: str = ""
    fullhunt: str = ""


class ReportingConfig(BaseModel):
    """Reporting output configuration."""

    auto_report: bool = True
    format: str = "html"
    include_screenshots: bool = True


class GeneralConfig(BaseModel):
    """General scan configuration."""

    threads: int = 50
    timeout: int = 10
    retries: int = 3
    user_agents: List[str] = Field(
        default_factory=lambda: [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
        ]
    )
    proxy: Optional[str] = None
    output_dir: str = "./output"
    output_format: str = "json"


class Config(BaseModel):
    """Top-level GODRECON configuration."""

    general: GeneralConfig = Field(default_factory=GeneralConfig)
    dns: DNSConfig = Field(default_factory=DNSConfig)
    modules: ModulesConfig = Field(default_factory=ModulesConfig)
    subdomains: SubdomainModuleConfig = Field(default_factory=SubdomainModuleConfig)
    dns_module: DNSModuleConfig = Field(default_factory=DNSModuleConfig)
    api_keys: APIKeysConfig = Field(default_factory=APIKeysConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    http_probe: HttpProbeConfig = Field(default_factory=HttpProbeConfig)
    tech_detection: TechDetectionConfig = Field(default_factory=TechDetectionConfig)
    ssl_analysis: SSLAnalysisConfig = Field(default_factory=SSLAnalysisConfig)
    port_scan: PortScanConfig = Field(default_factory=PortScanConfig)
    content_discovery: ContentDiscoveryConfig = Field(default_factory=ContentDiscoveryConfig)
    takeover: TakeoverConfig = Field(default_factory=TakeoverConfig)


def load_config(config_path: Optional[str] = None) -> Config:
    """Load configuration from a YAML file, applying environment variable overrides.

    Args:
        config_path: Optional path to a YAML configuration file. Defaults to
                     ``config.yaml`` in the current working directory.

    Returns:
        Populated :class:`Config` instance.
    """
    path = Path(config_path) if config_path else Path("config.yaml")

    raw: Dict[str, Any] = {}
    if path.exists():
        with path.open("r") as fh:
            raw = yaml.safe_load(fh) or {}

    # Environment variable overrides (GODRECON__SECTION__KEY=value)
    _apply_env_overrides(raw)

    return Config(**raw)


def _apply_env_overrides(raw: Dict[str, Any]) -> None:
    """Mutate *raw* in-place with values from environment variables.

    Environment variables follow the pattern ``GODRECON__<SECTION>__<KEY>``.
    For example ``GODRECON__GENERAL__THREADS=100``.
    """
    prefix = "GODRECON__"
    for env_key, env_val in os.environ.items():
        if not env_key.startswith(prefix):
            continue
        parts = env_key[len(prefix):].lower().split("__")
        if len(parts) == 2:
            section, key = parts
            raw.setdefault(section, {})[key] = env_val
