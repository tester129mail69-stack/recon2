# GODRECON — The Ultimate Cybersecurity Reconnaissance Tool

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-alpha-orange.svg)]()

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
- **AI-Powered** — ML-based false positive filtering and risk scoring (Phase 2)
- **Beautiful Reports** — HTML, PDF, JSON, CSV, Markdown output formats
- **Rich CLI** — Colourised output with progress bars, tables, and ASCII art

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

## Module List

| Module | Category | Status |
|--------|----------|--------|
| `subdomains` | Discovery | Active |
| `dns` | Discovery | Phase 2 |
| `http_probe` | Discovery | Phase 2 |
| `ports` | Scanning | Phase 2 |
| `tech` | Fingerprint | Phase 2 |
| `osint` | Intelligence | Phase 2 |
| `takeover` | Vulnerabilities | Phase 2 |
| `cloud` | Cloud | Phase 2 |
| `vulns` | Vulnerabilities | Phase 2 |
| `ssl` | Analysis | Phase 2 |
| `email_sec` | Analysis | Phase 2 |
| `screenshots` | Visual | Phase 2 |
| `api_intel` | Intelligence | Phase 2 |
| `crawl` | Discovery | Phase 2 |

---

## Architecture

```
godrecon/
├── cli.py              # Typer + Rich CLI interface
├── core/
│   ├── engine.py       # Async scan orchestrator
│   ├── config.py       # YAML configuration + env overrides
│   ├── scope.py        # Target & scope management
│   └── scheduler.py    # Async task queue with priority/retry
├── modules/
│   ├── base.py         # BaseModule abstract class
│   └── */              # Individual scan modules
├── utils/
│   ├── http_client.py  # Async HTTP with pooling, retry, UA rotation
│   ├── dns_resolver.py # Async DNS with caching, all record types
│   ├── logger.py       # Rich-based structured logging
│   └── helpers.py      # Utility functions
├── ai/                 # ML-based scoring & filtering (Phase 2)
├── reporting/          # HTML/PDF/JSON/CSV/Markdown reports
└── api/                # FastAPI REST server (Phase 3)
```

---

## Roadmap

- **Phase 1** (current): Core framework, async engine, CLI, HTTP/DNS clients
- **Phase 2**: Full module implementations, AI scoring, advanced reporting
- **Phase 3**: REST API, web dashboard, collaboration features
- **Phase 4**: Plugin marketplace, CI/CD integrations, enterprise features

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
