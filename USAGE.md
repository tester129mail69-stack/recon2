# GODRECON — Complete Usage Guide

This guide covers everything you need to install, configure, and run GODRECON.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
   - [Linux (Ubuntu/Debian/Kali)](#linux-ubuntudebiankali)
   - [macOS](#macos)
   - [Windows (PowerShell)](#windows-powershell)
   - [Docker](#docker)
3. [Running Scans](#running-scans)
4. [REST API Server](#rest-api-server)
5. [Web Dashboard](#web-dashboard)
6. [Continuous Monitoring](#continuous-monitoring)
7. [Configuration Guide](#configuration-guide)
8. [API Keys](#api-keys-optional-but-recommended)
9. [Running Tests](#running-tests)
10. [Troubleshooting](#troubleshooting)
11. [Legal Disclaimer](#legal-disclaimer)

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| **Python** | 3.10+ | [python.org](https://python.org) |
| **pip** | latest | Included with Python |
| **Git** | any | For cloning the repo |
| **Playwright** | optional | Required for screenshots |
| **Docker** | optional | Easiest cross-platform option |

---

## Installation

### Linux (Ubuntu/Debian/Kali)

```bash
# Update system
sudo apt update && sudo apt install -y python3 python3-pip python3-venv git

# Clone
git clone https://github.com/nothingmch69tester2mail69-afk/recon.git
cd recon

# Virtual environment
python3 -m venv venv
source venv/bin/activate

# Install
pip install -r requirements.txt

# (Optional) Screenshots
pip install playwright && playwright install chromium

# Verify
python main.py version
```

### macOS

```bash
brew install python@3.12 git
git clone https://github.com/nothingmch69tester2mail69-afk/recon.git
cd recon
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py version
```

### Windows (PowerShell)

```powershell
# Download Python 3.10+ from python.org — CHECK "Add to PATH" during install!
git clone https://github.com/nothingmch69tester2mail69-afk/recon.git
cd recon
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python main.py version
```

### Docker

```bash
git clone https://github.com/nothingmch69tester2mail69-afk/recon.git
cd recon
docker-compose up --build -d
# Run scans
docker-compose exec godrecon python main.py scan --target example.com
```

---

## Running Scans

### Basic Scans

```bash
# Quick subdomain scan (fastest)
python main.py scan --target example.com

# Full scan — ALL modules enabled
python main.py scan --target example.com --full

# Verbose mode — see everything happening
python main.py scan --target example.com --full -v

# Silent mode — minimal output (for scripts/piping)
python main.py scan --target example.com --silent
```

### Output Formats

```bash
# JSON output (default)
python main.py scan --target example.com -o results.json

# HTML report (beautiful, shareable)
python main.py scan --target example.com --full --format html -o report.html

# CSV output (for Excel/spreadsheets)
python main.py scan --target example.com --format csv -o results.csv

# Markdown output (for docs/GitHub)
python main.py scan --target example.com --format md -o report.md

# PDF report (for clients)
python main.py scan --target example.com --format pdf -o report.pdf
```

### Specific Modules

```bash
# Subdomains only
python main.py scan --target example.com --subs-only

# Port scanning
python main.py scan --target example.com --modules ports

# DNS intelligence
python main.py scan --target example.com --modules dns

# SSL/TLS analysis
python main.py scan --target example.com --modules ssl

# Technology detection
python main.py scan --target example.com --modules tech

# OSINT gathering
python main.py scan --target example.com --modules osint

# Cloud asset discovery
python main.py scan --target example.com --modules cloud

# Vulnerability scanning
python main.py scan --target example.com --modules vulns

# Subdomain takeover check
python main.py scan --target example.com --modules takeover

# Web crawling + JS analysis
python main.py scan --target example.com --modules crawl

# API intelligence
python main.py scan --target example.com --modules api_intel

# Network intelligence (traceroute, CDN bypass, ASN)
python main.py scan --target example.com --modules network

# Content discovery (directory brute-force)
python main.py scan --target example.com --modules content_discovery

# Screenshots
python main.py scan --target example.com --modules visual --screenshots

# Multiple modules at once
python main.py scan --target example.com --modules dns,ssl,tech,vulns
```

### Advanced Options

```bash
# Custom thread count (more = faster but more aggressive)
python main.py scan --target example.com --threads 200

# Custom timeout
python main.py scan --target example.com --timeout 15

# Through a proxy (Burp Suite, OWASP ZAP, etc.)
python main.py scan --target example.com --proxy http://127.0.0.1:8080

# SOCKS5 proxy (Tor)
python main.py scan --target example.com --proxy socks5://127.0.0.1:9050

# Custom config file
python main.py scan --target example.com --config my-config.yaml
```

---

## REST API Server

```bash
# Start the API server
python main.py api
# or with custom host/port
python main.py api --host 0.0.0.0 --port 8080
```

The API is available at `http://127.0.0.1:8000`.

- **Swagger UI docs**: `http://127.0.0.1:8000/docs`
- **Dashboard**: `http://127.0.0.1:8000/dashboard/`

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/scan` | Start a new scan |
| `GET` | `/api/v1/scan/{id}` | Get scan results by ID |
| `GET` | `/api/v1/scans` | List all scans |
| `DELETE` | `/api/v1/scan/{id}` | Delete a scan |

---

## Web Dashboard

```bash
# Start the API server (dashboard is included)
python main.py api

# Open browser to:
# http://127.0.0.1:8000/dashboard/
```

### Dashboard Pages

| Page | Description |
|------|-------------|
| **Home** | Overview, quick scan launcher, system status |
| **Scans** | Scan history with status and results |
| **Scan Detail** | Full results with findings table and risk gauge |
| **Attack Surface** | Visual map of subdomains, IPs, and open ports |
| **Findings** | All findings filterable by severity |
| **Settings** | Configure API keys, modules, and notifications |

---

## Continuous Monitoring

```bash
# Add a monitoring schedule
python main.py monitor add --target example.com --interval daily --notify slack

# List all schedules
python main.py monitor list

# Remove a schedule
python main.py monitor remove --id <schedule-id>

# Start the monitoring daemon
python main.py monitor run
```

### Notification Setup

Configure notifications in `config.yaml`:

**Slack**
```yaml
notifications:
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
```

**Discord**
```yaml
notifications:
  discord:
    enabled: true
    webhook_url: "https://discord.com/api/webhooks/YOUR/WEBHOOK/URL"
```

**Telegram**
```yaml
notifications:
  telegram:
    enabled: true
    bot_token: "YOUR_BOT_TOKEN"
    chat_id: "YOUR_CHAT_ID"
```

**Email (SMTP)**
```yaml
notifications:
  email:
    enabled: true
    smtp_host: "smtp.gmail.com"
    smtp_port: 587
    smtp_user: "you@gmail.com"
    smtp_pass: "your-app-password"
    from_addr: "you@gmail.com"
    to_addrs:
      - "recipient@example.com"
```

---

## Configuration Guide

All settings live in `config.yaml`. Key sections:

### `general`
| Key | Default | Description |
|-----|---------|-------------|
| `threads` | `50` | Number of concurrent tasks |
| `timeout` | `10` | Request timeout in seconds |
| `retries` | `3` | Retry attempts on failure |
| `proxy` | `null` | Proxy URL (http/socks5) |
| `output_dir` | `./output` | Directory for scan results |
| `output_format` | `json` | Default output format |

### `dns`
| Key | Default | Description |
|-----|---------|-------------|
| `resolvers` | `[8.8.8.8, 8.8.4.4, 1.1.1.1]` | DNS resolvers to use |
| `timeout` | `5` | DNS query timeout |

### `modules`
Enable or disable individual modules:
```yaml
modules:
  subdomains: true
  dns: true
  http_probe: true
  ports: false       # Disabled by default (requires elevated privileges for ports <1024)
  tech: true
  osint: true
  takeover: true
  cloud: true
  vulns: true
  crawl: false
  ssl: true
  email_sec: true
  screenshots: false # Disabled by default (requires Playwright)
  api_intel: true
  content_discovery: true
  network: true
```

### `api_keys`
Add API keys for enhanced OSINT capabilities:
```yaml
api_keys:
  shodan: ""
  censys_id: ""
  censys_secret: ""
  virustotal: ""
  securitytrails: ""
  binaryedge: ""
  hunter: ""
```

### `notifications`
Configure alert channels (Slack, Discord, Telegram, Email). See [Notification Setup](#notification-setup) above.

### `api`
```yaml
api:
  host: "127.0.0.1"
  port: 8000
  api_key: ""          # Set to require auth on API endpoints
  max_concurrent_scans: 3
```

### Environment Variable Overrides

Override any config value at runtime using the pattern `GODRECON__<SECTION>__<KEY>`:

```bash
export GODRECON__GENERAL__THREADS=100
export GODRECON__API_KEYS__SHODAN=your-shodan-key
export GODRECON__GENERAL__PROXY=http://127.0.0.1:8080
```

---

## API Keys (Optional but Recommended)

API keys unlock passive OSINT data from third-party services. All are free-tier eligible.

| Service | Sign-up URL | Config Key | What It Adds |
|---------|-------------|------------|--------------|
| **Shodan** | [shodan.io](https://shodan.io) | `api_keys.shodan` | Host data, open ports, banners |
| **VirusTotal** | [virustotal.com](https://virustotal.com) | `api_keys.virustotal` | Subdomains, malware, reputation |
| **Censys** | [censys.io](https://censys.io) | `api_keys.censys_id` / `api_keys.censys_secret` | Internet-wide scan data |
| **SecurityTrails** | [securitytrails.com](https://securitytrails.com) | `api_keys.securitytrails` | Historical DNS, subdomains |
| **BinaryEdge** | [binaryedge.io](https://binaryedge.io) | `api_keys.binaryedge` | Internet exposure data |
| **Hunter.io** | [hunter.io](https://hunter.io) | `api_keys.hunter` | Email address discovery |

Add keys directly to `config.yaml` or set them as environment variables:

```bash
export GODRECON__API_KEYS__SHODAN=abc123
export GODRECON__API_KEYS__VIRUSTOTAL=xyz789
```

---

## Running Tests

```bash
pip install pytest pytest-asyncio pytest-cov
pytest tests/ -v
pytest tests/ --cov=godrecon --cov-report=html
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `ModuleNotFoundError` | Activate the virtual environment: `source venv/bin/activate` (Linux/macOS) or `.\venv\Scripts\Activate.ps1` (Windows) |
| `Permission denied` on Linux | Use `sudo` for port scanning below 1024, or run with CAP_NET_RAW |
| Screenshots not working | Install Playwright: `pip install playwright && playwright install chromium` |
| Slow scans | Increase threads: `--threads 200` or set `general.threads` in `config.yaml` |
| API key errors | Check the `api_keys` section in `config.yaml` or verify your environment variables |
| `Connection refused` on API | Ensure the server is running: `python main.py api` |
| Docker build fails | Run `docker-compose build --no-cache` to force a clean rebuild |

---

## Legal Disclaimer

> **IMPORTANT**: Only scan targets you own or have explicit written permission to test.
> This tool is intended for educational purposes and authorized security testing only.
> Unauthorized scanning of systems you do not own may violate local laws and regulations.
> The developers assume no liability for misuse of this tool.
