# T-Web

CTF web challenge automation tool. Crawls targets with a real browser, maps the full attack surface, and runs 11 parallel attack modules.

Built for web-category CTF challenges where manual testing is too slow and generic scanners miss JS-heavy apps, SPA logins, and blind injection points.

---

## Features

- **Real browser crawler** — Playwright (Chromium) handles React/Vue/Next.js, executes JavaScript, captures XHR/fetch ghost APIs that static crawlers miss
- **11 attack modules** — SQLi, XSS, LFI, SSTI, SSRF, IDOR, NoSQL, Command Injection, JWT, XXE, File Upload
- **Path brute-force** — 151 CTF-focused paths probed in Phase 0 (flag targets, admin panels, backup files, debug endpoints, framework-specific paths); soft-404 filtered
- **JS endpoint mining** — fetches in-scope `.js` bundles and extracts `/api/`, `/rest/`, `/graphql/` paths; HEAD-validates and adds to attack surface
- **CORS misconfiguration detection** — passive check with a spoofed origin; reports wildcard + credentials and reflected-origin patterns
- **Session handoff** — browser login (cookies, JWT, CSRF tokens) is transferred to the HTTP client; works with OAuth2, SPA login flows, DVWA security levels
- **OOB callback server** — embedded HTTP listener detects blind SSRF, blind CMDi, and out-of-band SQLi
- **WAF bypass** — 5 tamper techniques (case, encoding, comment insertion) auto-applied on block
- **Dynamic flag detection** — finds flags in JSON values, base64 blobs, HTML comments, response headers — not just `FLAG{...}` patterns
- **Burp Suite compatible** — `--proxy http://127.0.0.1:8080 --no-verify` routes all traffic through Burp

---

## Requirements

- Python **3.10+**
- Linux or macOS recommended (OOB server requires a routable network IP)
- On Windows the tool works but OOB callbacks won't arrive on loopback-only interfaces

---

## Installation

```bash
git clone https://github.com/ARSTaha/T-Web.git
cd T-Web

python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt
playwright install --with-deps chromium
```

---

## Usage

```bash
# Full scan — all 11 modules
python main.py -u https://target.ctf/

# Target specific vectors
python main.py -u https://target.ctf/ --attacks sqli,xss,lfi,cmdi,jwt

# Authenticated target
python main.py -u https://target.ctf/ --login /login --user admin --pass password

# Behind Burp Suite proxy
python main.py -u https://target.ctf/ --proxy http://127.0.0.1:8080 --no-verify

# Slow down for sensitive/monitored CTF infra
python main.py -u https://target.ctf/ --rate-limit 3 --delay 0.5 --concurrency 3
```

---

## Example Output

```
╭───────────────────────────╮
│ T-Web CTF Web Attack Tool │
│ by Tajaa                  │
╰───────────────────────────╯
  OOB server: http://10.10.14.5:9999

🔍  Phase 0: Passive Recon
  [200] robots.txt — Disallow: /admin
  [200] phpinfo.php — PHP 8.1, Linux

🕷  Phase 1: Active Crawl
  Playwright login complete
  → https://target.ctf/dashboard
  → https://target.ctf/api/v1/users
  Attack points: 18 | Ghost APIs: 3

⚔  Phase 2: Parallel Attack
  [SQLi] Error-based hit! Payload: "'"
  [CMDi] Time-based hit! (3.0s, baseline 0.0s) Payload: '; sleep 3 #'
  [LFI]  File read! Payload: '../../../../etc/passwd'
  [JWT]  alg:none bypass! alg='none'

🚩  Phase 3: Results
╭──────────────────┬──────────────────────────────────┬────────────────╮
│ Type             │ Value                            │ Confidence     │
├──────────────────┼──────────────────────────────────┼────────────────┤
│ sqli_error       │ Error-based SQLi @ /search ?q    │ ███████░ 90%   │
│ cmdi_time_based  │ Command Injection @ /ping ?ip    │ ██████░░ 85%   │
│ lfi_file_read    │ LFI @ /view ?file → /etc/passwd  │ ███████░ 95%   │
│ jwt_none_sig     │ JWT alg:none bypass @ /api/me    │ ███████░ 95%   │
╰──────────────────┴──────────────────────────────────┴────────────────╯
```

---

## Attack Modules

| Module | Detection Techniques |
|--------|---------------------|
| `sqli` | Error-based, time-based blind (SLEEP), boolean-blind (response length diff), HTTP header injection |
| `xss` | Reflected (GET/POST params), stored (form submission), header-based (User-Agent, Referer) |
| `lfi` | Path traversal (`../`), null byte (`%00`), absolute path, encoding variants |
| `ssti` | Jinja2 (`{{7*7}}`), Twig, Freemarker, Velocity expression probes |
| `ssrf` | HTTP/dict/gopher scheme injection, OOB callback verification |
| `idor` | Sequential integer ID enumeration, response size and content diff |
| `nosql` | MongoDB operator injection (`$gt`, `$ne`, `$where`, `$regex`) |
| `cmdi` | Time-based (sleep/timeout), OOB (curl/wget callback), error signature detection |
| `jwt` | Algorithm confusion (alg:none × 3 case variants), HS256 weak secret brute-force (30 common secrets), claim-based privilege escalation |
| `xxe` | XML External Entity file read via raw POST body (`application/xml`, `text/xml`); detects `/etc/passwd`, flag files, `/proc/self/environ` in response |
| `upload` | File upload bypass: extension variants (`.php5`, `.phtml`, `.phar`), MIME-type spoof, magic byte prepend, double extension; RCE confirmed via unique marker before reporting |

---

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `-u` | required | Target URL |
| `--attacks` | all | Modules: `sqli,xss,ssrf,lfi,ssti,idor,nosql,cmdi,jwt,xxe,upload` |
| `--login` | — | Login path (e.g. `/login`) |
| `--user` | — | Username |
| `--pass` | — | Password |
| `--proxy` | — | HTTP proxy (e.g. `http://127.0.0.1:8080`) |
| `--no-verify` | false | Disable TLS verification |
| `--rate-limit` | 5.0 | Max requests per second (token bucket) |
| `--delay` | 0.0 | Fixed delay between requests (seconds) |
| `--concurrency` | 5 | Max concurrent HTTP connections |
| `--max-pages` | 50 | Max pages crawled by Playwright |

---

## Architecture

### Execution Flow

```
Phase 0  Passive recon   151 paths probed (paths.txt + built-ins): robots.txt, .git, admin panels,
                         backup files, phpinfo, framework endpoints; soft-404 filtered.
                         CORS misconfiguration check runs here (spoofed Origin header).
Phase 1  Active crawl    Playwright navigates pages, captures forms + XHR ghost APIs.
                         JS bundle mining extracts /api/ and /rest/ paths from .js files.
Phase 2  Parallel attack asyncio.gather runs all 10 modules concurrently per attack point.
Phase 3  Results         CORS findings prepended, all findings ranked by confidence, printed.
```

### Session Handoff

After Playwright login, `session_bridge.py` extracts cookies, JWT tokens (from localStorage, sessionStorage, cookies), and CSRF tokens from the live DOM. These are transferred to an `httpx.AsyncClient`, so every attack request carries the same authenticated state the browser established — including security-level cookies (e.g. DVWA's `security=low`).

### Parallel Attack Model

Each crawled form field and URL parameter becomes an *attack point*. All enabled modules run against all attack points concurrently via `asyncio.gather`. Time-based modules (SQLi, CMDi) use `asyncio.Semaphore(1)` to serialize sleep payloads — preventing parallel sleeps from inflating each other's timing measurements.

### Time-Based Detection

Baseline response time is measured with a benign payload (empty string). The sleep payload is then sent and timed. A hit is recorded when:

```
elapsed ≥ 2.8s  AND  (elapsed − baseline) ≥ 1.5s
```

The differential threshold (1.5 s) tolerates server-side variability (e.g. a `ping -c 4` that takes ~1 s) without generating false positives.

### Boolean-Blind SQLi

True/false payloads are sent and their response sizes compared. Threshold:

```
|true_len − false_len| ≥ max(50, max(true_len, false_len) × 5%)
```

The percentage-based floor catches small pages where an absolute byte threshold would miss the difference.

### OOB Server

An `aiohttp` TCP site binds on `0.0.0.0:9999` and auto-detects the machine's routable IP. SSRF and CMDi payloads inject `curl`/`wget` callbacks to this URL. If the target reaches out, the connection is logged with source IP and timestamp — confirming blind execution without relying on response content.

### JWT Module

Implemented with Python stdlib only (`base64`, `hmac`, `hashlib`) — no PyJWT dependency. Performs:
1. **alg:none bypass** — three case variants (`none`, `None`, `NONE`) since some implementations are case-sensitive
2. **Weak secret brute-force** — CPU-only HMAC comparison against 30 common secrets before sending any network request
3. **Privilege escalation** — rewrites `role`, `is_admin`, `admin`, `group`, `sub` claims if a working signing method is found

A protected endpoint is identified by checking that the valid token returns 200 and an invalid token returns 401/403 — preventing false positives against public endpoints.

---

## Notes

- Designed for **CTF web challenges** — not for use on systems without explicit authorization
- OOB callbacks require a **routable IP** (CTF VPN, HTB/THM tunnel, or your lab's network interface)
- JWT module targets HS256 and alg:none; RS256/ES256 key confusion is out of scope
- NoSQL module targets MongoDB patterns; other NoSQL databases may need custom payloads

---

## Author

Tajaa
