# API Security Scanner — Bug Bounty Edition

> **One file. Zero dependencies. Works on Windows, Mac, Linux.**
> Give it any URL — it discovers everything and finds vulnerabilities automatically.

---

## Quick Start

```bash
# Scan any website — discovers API endpoints automatically
python api_scanner.py --url https://target.com

# Direct API URL — scans immediately
python api_scanner.py --url https://target.com/api/v1 --token YOUR_TOKEN

# Map the attack surface only
python api_scanner.py --url https://target.com --discover-only

# Full scan, save all reports
python api_scanner.py --url https://target.com --full-scan --output my_scan

# Against VulnAPI (local practice)
python api_scanner.py --url http://localhost:5000
```

---

## How It Works

### If you give a base URL (e.g. https://target.com)
1. **Discovery** — probes 40+ common paths to find API endpoints, GraphQL, Swagger docs
2. **JS scanning** — reads JavaScript files for hidden API paths
3. **Swagger parsing** — downloads and parses OpenAPI specs to find more endpoints
4. **Scanning** — runs all vulnerability modules against discovered endpoints
5. **Reporting** — saves HTML, JSON, CSV, Markdown, SARIF reports

### If you give a direct API URL (e.g. https://target.com/api/v1)
- Skips discovery, scans immediately

---

## Modules

| Module | Finds | OWASP |
|---|---|---|
| `graphql` | Introspection, private fields, batch queries, field suggestions | API3, API8 |
| `bola` | Unauth object access, sequential IDs, verb tampering, query param IDOR | API1 |
| `auth` | Unauthenticated endpoints, method override, privilege escalation | API2, API5 |
| `headers` | CORS origin reflection, missing HSTS/CSP/XFO, server disclosure | API8 |
| `jwt` | alg:none bypass, weak secrets, missing expiry, missing claims | API2 |
| `sensitive` | SSNs, credit cards, AWS keys, DB strings, stack traces, verbose errors | API3 |
| `ratelimit` | Missing limits, IP spoof bypass, high latency | API4 |
| `fuzz` | SQLi, SSTI, path traversal, command injection, open redirect | API8 |
| `mass-assignment` | Hidden field acceptance, price/role manipulation | API3 |

---

## All Options

```
--url URL            Target URL (required)
--token TOKEN        Bearer token / JWT / API key
--module MODULE      Run specific module(s) — repeat for multiple
--full-scan          Run all 9 modules
--discover-only      Map endpoints only, no vulnerability scanning
--no-discover        Skip discovery, scan given URL directly
--scan-all           Scan every discovered endpoint (more thorough, slower)
--params PARAMS      Query params to fuzz, e.g. q,id,search
--requests N         Burst size for rate limit testing (default: 30)
--timeout N          Request timeout seconds (default: 12)
--no-ssl-verify      Disable SSL certificate verification
--output STEM        Report filename stem (e.g. my_scan)
--format FORMAT      html | json | csv | markdown | sarif | all
--verbose            Show all findings, not just critical/high
--threads N          Discovery thread count (default: 20)
```

---

## Report Formats

| Format | Use |
|---|---|
| `.html` | Interactive browser report — click findings to expand |
| `.json` | Machine-readable — import into other tools |
| `.csv` | Excel / spreadsheet tracking |
| `.md` | Markdown — paste into documentation or GitHub issues |
| `.sarif` | GitHub Code Scanning / Security tab upload |

---

## Practice Against VulnAPI

```bash
# Start VulnAPI (Terminal 2)
cd vuln-api
python app.py

# Scan it (Terminal 1)
python api_scanner.py --url http://localhost:5000 --full-scan --output vulnapi_report
start vulnapi_report.html
```

Expected: 9+ CRITICAL, 10+ HIGH findings

---

## Requirements

- Python 3.9 or higher
- Nothing else — no pip, no venv, no Docker

---

## Legal

Authorized security testing only. Never scan targets you do not own or lack written permission to test.
