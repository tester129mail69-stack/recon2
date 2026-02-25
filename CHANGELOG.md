# Changelog

All notable changes to GODRECON will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-02-25

### Added
- WHOIS reconnaissance module
- Wayback Machine URL history module
- GitHub dorking module for leaked secrets
- WAF detection module (10+ WAF signatures)
- CORS misconfiguration scanner
- GraphQL introspection scanner
- JWT vulnerability scanner
- Favicon hash fingerprinting module
- Enhanced subdomain takeover checks (30+ services)
- Scan profiles system (quick, full, stealth, web-app, infrastructure, osint)
- Plugin SDK with `create-module` scaffold command
- Pre-commit hooks configuration
- PyPI publishing workflow
- README badges (CI, Python version, license, code style)

## [0.2.0] - 2026-02-25

### Added
- SQLite persistent scan storage
- Scan result diffing (`godrecon diff`)
- CLI enhancements: `--quiet`, `--json-output`, `--timeout`, `--verbose`, `--debug`
- Input validation utilities
- Comprehensive unit tests for all 17 original modules
- GitHub Actions CI workflow
- CONTRIBUTING.md and SECURITY.md
- Ruff linting configuration

## [0.1.0] - 2026-02-24

### Added
- Initial release with core scan engine
- 17 reconnaissance modules (subdomains, DNS, HTTP, SSL, ports, vulns, crawl, tech, cloud, OSINT, visual, email_sec, screenshots, takeover, api_intel, content_discovery, network)
- Typer CLI with Rich terminal interface
- FastAPI REST API with scan management
- Web dashboard
- Continuous monitoring with notifications
- Docker support
- Multiple report formats (JSON, HTML, CSV, Markdown, PDF)
