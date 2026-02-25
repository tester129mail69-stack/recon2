# GODRECON — The Ultimate Cybersecurity Reconnaissance Tool

[![CI](https://github.com/tester129mail69-stack/recon2/actions/workflows/ci.yml/badge.svg)](https://github.com/tester129mail69-stack/recon2/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

```
 ██████╗  ██████╗ ██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔════╝ ██╔═══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██║  ███╗██║   ██║██║  ██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██║   ██║██║   ██║██║  ██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
╚██████╔╝╚██████╔╝██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═════╝  ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
```

> **The only recon tool you'll ever need.**
> Async-first, modular, extensible, and blazing fast.

---

## Features

- **Subdomain Enumeration** — Brute-force, passive DNS, certificate transparency
- **DNS Intelligence** — All record types (A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, CAA)
- **HTTP Probing** — Status codes, response times, redirect chains, technology detection
- **Port Scanning** — Fast async TCP port scanning with banner grabbing
- **Vulnerability Detection** — CVE correlation, misconfiguration checks
- **Subdomain Takeover** — Detect dangling DNS records pointing to unclaimed services
- **Cloud Asset Discovery** — S3 buckets, Azure blobs, GCP storage, CloudFront
- **SSL/TLS Analysis** — Certificate transparency, cipher suites, expiry dates
- **Email Security** — SPF, DKIM, DMARC misconfiguration detection
- **Screenshots** — Automated web screenshots for discovered assets
- **OSINT Integration** — Shodan, Censys, VirusTotal, SecurityTrails, BinaryEdge
- **AI-Powered Analysis** — Rule-based and OpenAI-backed risk scoring, executive summaries, remediation priorities
- **Multi-Target Campaigns** — Scan multiple targets concurrently with aggregated reporting
- **Stealth Mode** — Randomized delays, User-Agent rotation, proxy support
- **Webhook / SIEM** — Push findings to Slack, Discord, generic webhooks, or Splunk HEC
- **SARIF Export** — SARIF v2.1.0 output for enterprise CI/CD integration
- **Scan Checkpoints** — Resume interrupted scans from where they left off
- **Adaptive Rate Limiter** — Automatically backs off on 429/503 responses
- **Scope Configuration** — YAML-based in-scope / out-of-scope rules (domains, CIDRs, wildcards)
- **Beautiful Reports** — HTML, PDF, JSON, CSV, Markdown, SARIF output formats
- **Rich CLI** — Colourised output with progress bars, tables, and ASCII art

---

## 🤖 AI-Powered Analysis

```bash
# Analyze a stored scan result
godrecon analyze <scan_id>

# Use OpenAI GPT for deeper analysis
godrecon analyze <scan_id> --provider openai --api-key $OPENAI_KEY
```

---

## 🎯 Multi-Target Campaigns

```bash
# targets.txt: one target per line, # for comments
godrecon campaign targets.txt --name "Q1 Audit" --concurrent 5

# Save report and use a scan profile
godrecon campaign targets.txt --profile quick -o campaign.json
```

---

## 🥷 Stealth Mode

```bash
godrecon scan --target example.com --stealth --min-delay 2 --max-delay 10 --proxy socks5://127.0.0.1:9050
```

---

## 🔔 Webhook / SIEM Integration

Configure in `config.yaml`:
```yaml
notifications:
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/..."
  discord:
    enabled: true
    webhook_url: "https://discord.com/api/webhooks/..."
```

---

## 📋 SARIF Export

```bash
godrecon scan --target example.com --format sarif -o results.sarif
```

---

## ↩️ Scan Resume

```bash
# Scans save checkpoints automatically; resume with:
godrecon resume <scan_id>
```

---

## 🎯 Scope Configuration

```yaml
# scope.yaml
scope:
  in_scope:
    - "*.example.com"
    - "10.0.0.0/8"
  out_of_scope:
    - "production.example.com"
    - "10.0.1.0/24"
```

```bash
godrecon scan --target api.example.com --scope scope.yaml
```

---


## Quick Install

### pip (recommended)

```bash
pip install -r requirements.txt
python main.py --help
```

### Docker

```bash
docker-compose build
docker-compose run godrecon scan --target example.com
```

---

## Supported Platforms

| OS | Supported | Notes |
|----|-----------|-------|
| **Linux** (Ubuntu 20.04+, Kali, Debian, Fedora, Arch) | ✅ Recommended | Best performance, full feature support |
| **macOS** (12 Monterey+) | ✅ Full Support | Install via Homebrew for Python 3.10+ |
| **Windows 10/11** | ✅ Full Support | Use PowerShell or WSL2 recommended |
| **Docker** (any OS) | ✅ Full Support | Easiest cross-platform option |

### Requirements
- **Python 3.10+** (required)
- **pip** (comes with Python)
- **Playwright** (optional, for screenshots): `pip install playwright && playwright install chromium`

---

## Installation & Setup

### Linux (Ubuntu/Debian/Kali)
```bash
# 1. Install Python 3.10+ if not already installed
sudo apt update && sudo apt install -y python3 python3-pip python3-venv git

# 2. Clone the repo
git clone https://github.com/nothingmch69tester2mail69-afk/recon.git
cd recon

# 3. Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. (Optional) Install Playwright for screenshots
pip install playwright && playwright install chromium

# 6. Run GODRECON
python main.py scan --target example.com
```

### macOS
```bash
# 1. Install Python via Homebrew
brew install python@3.12 git

# 2. Clone and setup
git clone https://github.com/nothingmch69tester2mail69-afk/recon.git
cd recon
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Run
python main.py scan --target example.com
```

### Windows
```powershell
# 1. Install Python 3.10+ from python.org (check "Add to PATH")
# 2. Open PowerShell

git clone https://github.com/nothingmch69tester2mail69-afk/recon.git
cd recon
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Run
python main.py scan --target example.com
```

### Docker (Any OS)
```bash
git clone https://github.com/nothingmch69tester2mail69-afk/recon.git
cd recon
docker-compose build
docker-compose run godrecon scan --target example.com
```

---

## Quick Start

```bash
# Basic subdomain scan
python main.py scan --target example.com

# Full scan with HTML report
python main.py scan --target example.com --full --format html -o report.html

# Subdomains only, verbose
python main.py scan --target example.com --subs-only --verbose

# With proxy and custom threads
python main.py scan --target example.com --proxy http://127.0.0.1:8080 --threads 100

# Silent mode for scripting
python main.py scan --target example.com --silent --format json -o results.json
```

---

## 📖 Full Documentation

For the complete guide on installation, configuration, all scan commands, REST API, dashboard, monitoring, and troubleshooting, see **[USAGE.md](USAGE.md)**.

---

## 🖥️ Web Dashboard & API

```bash
# Start the server
python main.py api

# Dashboard: http://127.0.0.1:8000/dashboard/
# API Docs:  http://127.0.0.1:8000/docs
```

## 📡 Continuous Monitoring

```bash
# Schedule daily scans with Slack alerts
python main.py monitor add --target example.com --interval daily --notify slack

# Start monitoring daemon
python main.py monitor run
```

## 🐳 Docker

```bash
# Build and run
docker-compose build
docker-compose run godrecon scan --target example.com --full

# Start API + Dashboard
docker-compose run -p 8000:8000 godrecon api --host 0.0.0.0

# Results saved to ./output/
```

---

## Usage Examples

```bash
# Run only subdomain enumeration
python main.py scan --target example.com --modules subdomains

# Port scan with banner grabbing
python main.py scan --target example.com --modules ports --verbose

# SSL/TLS analysis only
python main.py scan --target example.com --modules ssl

# OSINT gathering
python main.py scan --target example.com --modules osint

# Check for subdomain takeovers
python main.py scan --target example.com --modules takeover

# Cloud asset discovery (S3, Azure, GCP)
python main.py scan --target example.com --modules cloud

# Vulnerability scan with CVE lookup
python main.py scan --target example.com --modules vulns

# Web crawl with JS analysis
python main.py scan --target example.com --modules crawl

# Full scan, all modules, JSON output
python main.py scan --target example.com --full --format json -o results.json

# Start the REST API server
python main.py api --host 127.0.0.1 --port 8000
```

---

## CLI Reference

```
godrecon scan [OPTIONS]

Options:
  -t, --target TEXT        Target domain, IP, or CIDR  [required]
  --full                   Run all modules
  --subs-only              Subdomain enumeration only
  --ports                  Enable port scanning
  --screenshots            Enable screenshots
  -o, --output PATH        Output file path
  -f, --format TEXT        Output format: json/csv/html/pdf/md [default: json]
  --threads INT            Concurrency level [default: 50]
  --timeout INT            Request timeout in seconds [default: 10]
  --proxy TEXT             Proxy URL (http/socks5)
  --silent                 Minimal output
  -v, --verbose            Verbose output
  --config PATH            Custom config file path
  --help                   Show this message and exit

godrecon config [OPTIONS]
  --show                   Print current configuration
  --config PATH            Config file path

godrecon version
  Show GODRECON version information
```

---

## Configuration

Edit `config.yaml` to configure GODRECON:

```yaml
general:
  threads: 50        # Concurrent tasks
  timeout: 10        # Request timeout (seconds)
  retries: 3         # Retry attempts
  proxy: null        # Optional proxy URL
  output_dir: ./output

dns:
  resolvers:
    - "8.8.8.8"
    - "8.8.4.4"
    - "1.1.1.1"

modules:
  subdomains: true
  dns: true
  ports: false       # Disabled by default
  screenshots: false # Disabled by default

api_keys:
  shodan: ""
  virustotal: ""
```

Environment variable overrides follow the pattern `GODRECON__<SECTION>__<KEY>`:

```bash
export GODRECON__GENERAL__THREADS=100
export GODRECON__API_KEYS__SHODAN=your-key-here
```

---

## 🔧 Modules

| Module | Category | Description |
|--------|----------|-------------|
| `subdomains` | Recon | Subdomain enumeration via multiple sources |
| `dns` | Recon | DNS record analysis and intelligence |
| `http` | HTTP | HTTP probing and header analysis |
| `ssl` | Security | SSL/TLS certificate analysis |
| `ports` | Network | Port scanning and service detection |
| `vulns` | Security | Vulnerability pattern matching |
| `crawl` | Web | Web crawling, form extraction, JS analysis |
| `tech` | Recon | Technology stack detection |
| `cloud` | Cloud | Cloud infrastructure detection |
| `osint` | OSINT | Open-source intelligence gathering |
| `visual` | Recon | Visual similarity and page classification |
| `email_sec` | Security | Email security (SPF/DKIM/DMARC) |
| `screenshots` | Visual | Website screenshot capture |
| `takeover` | Security | Subdomain takeover detection (30+ services) |
| `api_intel` | API | API endpoint discovery |
| `content_discovery` | Web | Hidden content and directory brute-forcing |
| `network` | Network | Network reconnaissance |
| `whois` | OSINT | Domain WHOIS registration lookup |
| `wayback` | OSINT | Wayback Machine URL history |
| `github_dork` | OSINT | GitHub code search for leaked secrets |
| `waf` | HTTP | WAF detection and fingerprinting |
| `cors` | Security | CORS misconfiguration detection |
| `graphql` | API | GraphQL introspection scanning |
| `jwt` | Security | JWT vulnerability detection |
| `favicon` | Recon | Favicon hash fingerprinting |

---

## Shell Completions

GODRECON supports auto-completion for bash, zsh, and fish shells:

```bash
# Bash
godrecon --install-completion bash

# Zsh
godrecon --install-completion zsh

# Fish
godrecon --install-completion fish
```

---

## Architecture

```
godrecon/
├── __init__.py
├── cli.py              # Typer + Rich CLI interface
├── core/
│   ├── engine.py       # Async scan orchestrator
│   ├── config.py       # YAML configuration + env overrides + Pydantic models
│   ├── scope.py        # Target & scope management
│   └── scheduler.py    # Async task queue with priority/retry
├── modules/
│   ├── base.py         # BaseModule abstract class
│   ├── subdomains/     # Subdomain enumeration (40+ sources)
│   ├── dns/            # DNS intelligence + email security
│   ├── http/           # HTTP probing + security headers + content discovery
│   ├── ssl/            # SSL/TLS analysis
│   ├── tech/           # Technology fingerprinting (99 signatures)
│   ├── ports/          # Port scanning + banner grabbing
│   ├── takeover/       # Subdomain takeover detection (102 fingerprints)
│   ├── content_discovery/  # Directory/file brute-forcing
│   ├── osint/          # WHOIS, social media, Google dorks, metadata
│   ├── cloud/          # AWS S3, Azure Blob, GCP Storage enumeration
│   ├── crawl/          # Web spider + form finder + JS analyzer
│   ├── api_intel/      # API discovery + security checks
│   ├── vulns/          # CVE lookup + pattern matching + posture scoring
│   ├── network/        # Traceroute, CDN bypass, ASN, geolocation
│   ├── visual/         # Visual reconnaissance
│   └── screenshots/    # Screenshot capture
├── ai/                 # Risk scoring & false-positive filtering
├── api/                # FastAPI REST server
├── dashboard/          # Web dashboard
├── data/               # JSON databases (ports, services, fingerprints, templates)
├── reporting/          # HTML/PDF/JSON/CSV/Markdown report generators
└── utils/
    ├── http_client.py  # Async HTTP with pooling, retry, UA rotation
    ├── dns_resolver.py # Async DNS with caching, all record types
    ├── logger.py       # Rich-based structured logging
    └── helpers.py      # Utility functions
```

---

## Roadmap

- ✅ **Phase 1**: Core framework, async engine, CLI, HTTP/DNS clients
- ✅ **Phase 2**: Full module implementations, AI scoring, advanced reporting
- ✅ **Phase 3**: REST API, web dashboard, continuous monitoring
- 🔮 **Phase 4**: Plugin marketplace, CI/CD integrations, enterprise features

---

## Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/my-module`)
3. Add your module under `godrecon/modules/`
4. Inherit from `BaseModule` and implement `_execute`
5. Submit a Pull Request

---

## License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

*Built with love for the security community.*
