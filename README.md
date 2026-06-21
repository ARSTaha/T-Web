# T-Web

CTF web challenge automation tool. Crawls targets with a real browser, maps attack surfaces, and runs parallel attacks.

## Features

- **Playwright crawler** — handles React/Vue/Next.js, captures ghost APIs (XHR/fetch)
- **9 attack modules** — SQLi, XSS, SSRF, LFI, SSTI, IDOR, NoSQL, Command Injection, JWT
- **Session persistence** — cookies, JWT, CSRF tokens carried from browser to HTTP client
- **WAF detection + bypass** — 5 tamper techniques applied automatically
- **Dynamic flag detection** — finds flags in JSON keys, IPs, base64, HTML comments, not just `FLAG{...}` format
- **OOB server** — detects blind vulnerabilities (SSRF, blind CMDi, blind SQLi)
- **Burp Suite compatible** — `--proxy http://127.0.0.1:8080 --no-verify`

## Requirements

- Python 3.10+
- Linux / macOS (OOB server needs a routable IP — use on Kali, Parrot, or your CTF VPN interface)

## Installation

```bash
git clone https://github.com/ARSTaha/T-Web.git
cd T-Web

python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

pip install -r requirements.txt
playwright install --with-deps chromium
```

## Usage

```bash
# Basic scan — all 9 modules
python main.py -u https://target.ctf/

# Specific vectors only
python main.py -u https://target.ctf/ --attacks sqli,xss,lfi,cmdi,jwt

# With login
python main.py -u https://target.ctf/ --login /login --user admin --pass test

# With Burp proxy
python main.py -u https://target.ctf/ --proxy http://127.0.0.1:8080 --no-verify

# Rate limiting (CTF infra protection)
python main.py -u https://target.ctf/ --rate-limit 3 --delay 0.5 --concurrency 3
```

## Attack Modules

| Module | Techniques |
|--------|-----------|
| `sqli` | Error-based, time-based blind, boolean-blind, header injection |
| `xss` | Reflected, stored (form POST), header-based |
| `lfi` | Path traversal, null byte, encoding variants |
| `ssti` | Jinja2, Twig, Freemarker, Velocity probes |
| `ssrf` | HTTP, dict, gopher schemes; OOB callback |
| `idor` | Sequential ID enumeration, response diff |
| `nosql` | MongoDB operator injection (`$gt`, `$where`, `$regex`) |
| `cmdi` | Time-based (sleep), OOB (curl/wget callback), error-based |
| `jwt` | alg:none bypass, weak HS256 secret brute-force, privilege escalation |

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `-u` | required | Target URL |
| `--attacks` | all | Comma-separated: `sqli,xss,ssrf,lfi,ssti,idor,nosql,cmdi,jwt` |
| `--login` | — | Login endpoint path (e.g. `/login`) |
| `--user` | — | Username |
| `--pass` | — | Password |
| `--proxy` | — | HTTP proxy (e.g. Burp: `http://127.0.0.1:8080`) |
| `--no-verify` | false | Disable SSL verification |
| `--rate-limit` | 5.0 | Requests per second |
| `--delay` | 0.0 | Min delay between requests (seconds) |
| `--concurrency` | 5 | Max concurrent connections |
| `--max-pages` | 50 | Max pages to crawl |

## How It Works

```
Phase 0 — Passive recon    (robots.txt, .git, .env, backup files, phpinfo...)
Phase 1 — Active crawl     (Playwright, ghost API capture, form extraction)
Phase 2 — Parallel attack  (9 modules, WAF bypass on block, OOB detection)
Phase 3 — Results          (findings ranked by confidence)
```

## Author

Tajaa
