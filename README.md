# T-Web

CTF web challenge automation tool. Crawls targets with a real browser, maps attack surfaces, and runs parallel attacks.

## Features

- **Playwright crawler** — handles React/Vue/Next.js, captures ghost APIs (XHR/fetch)
- **7 attack modules** — SQLi, XSS, SSRF, LFI, SSTI, IDOR, NoSQL injection
- **Session persistence** — cookies, JWT, CSRF tokens carried from browser to HTTP client
- **WAF detection + bypass** — 5 tamper techniques applied automatically
- **Dynamic flag detection** — finds flags in JSON keys, IPs, base64, HTML comments, not just `FLAG{...}` format
- **OOB server** — detects blind vulnerabilities (SSRF, blind SQLi)
- **Burp Suite compatible** — `--proxy http://127.0.0.1:8080 --no-verify`

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
# Basic
python main.py -u https://target.ctf/

# With Burp proxy
python main.py -u https://target.ctf/ --proxy http://127.0.0.1:8080 --no-verify

# Specific vectors only
python main.py -u https://target.ctf/ --attacks sqli,xss,lfi

# With login
python main.py -u https://target.ctf/ --login /login --user admin --pass test

# Rate limiting
python main.py -u https://target.ctf/ --rate-limit 3 --delay 0.5 --concurrency 3
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `-u` | required | Target URL |
| `--proxy` | — | HTTP proxy (e.g. Burp: `http://127.0.0.1:8080`) |
| `--no-verify` | false | Disable SSL verification |
| `--attacks` | all | Comma-separated vector list: `sqli,xss,ssrf,lfi,ssti,idor,nosql` |
| `--login` | — | Login endpoint path (e.g. `/login`) |
| `--user` | — | Username for login |
| `--pass` | — | Password for login |
| `--rate-limit` | 5.0 | Requests per second |
| `--delay` | 0.0 | Minimum delay between requests (seconds) |
| `--concurrency` | 5 | Max concurrent connections |
| `--max-pages` | 50 | Max pages to crawl |

## How It Works

```
Phase 0 — Passive recon    (robots.txt, .git, .env, backup files...)
Phase 1 — Active crawl     (Playwright, ghost API capture, form mapping)
Phase 2 — Parallel attack  (7 modules run concurrently, WAF bypass if needed)
Phase 3 — Results          (findings ranked by confidence)
```

## Author

Tajaa
