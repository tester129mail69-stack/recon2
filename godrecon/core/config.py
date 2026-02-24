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
    api_keys: APIKeysConfig = Field(default_factory=APIKeysConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)


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
