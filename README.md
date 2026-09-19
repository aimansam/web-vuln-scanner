# Web Vuln Scanner

```text
      /\\
     /  \\
    / /\\ \\
   /_/  \\_\\   VULNSCAN
   \\  /\\  /   authorized web assessment
    \\//\\//
```

Lightweight web vulnerability scanner in Python — scans for SQLi, XSS, path traversal, sensitive files, and more. CLI-driven, modular scanner architecture.

[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)


## Features

- **SQL Injection** detection with error-based and boolean-based checks
- **Cross-Site Scripting (XSS)** detection with reflected XSS tests
- **Path Traversal** detection for common sensitive file paths
- **Sensitive Files** discovery (backup files, config files, admin panels)
- **Crawler** module to discover links and forms
- **Session management** with cookie handling
- **CLI interface** built with Click
- **Report generation** in multiple formats

## Installation

```bash
pip install web-vuln-scanner
# or clone and install:
git clone https://github.com/aimansam/web-vuln-scanner
cd web-vuln-scanner
pip install -e .
```

## Quick Start

Scan a target URL for common vulnerabilities:

```bash
web-vuln-scanner scan https://example.com
```

Scan with specific modules:

```bash
web-vuln-scanner scan https://example.com --modules sqli,xss,traversal
```

Crawl and discover endpoints first:

```bash
web-vuln-scanner crawl https://example.com
```

Generate a report:

```bash
web-vuln-scanner report --output report.json
```

## Modules

| Module | Description |
|--------|-------------|
| `sqli` | SQL injection detection |
| `xss` | Cross-site scripting detection |
| `traversal` | Path traversal detection |
| `sensitive_files` | Sensitive file discovery |
| `crawler` | Link and form discovery |
| `auth` | Authentication handling |

## Requirements

- Python 3.9+
- requests
- click
- beautifulsoup4

## License

MIT
