# T-Web

CTF web challenge automation tool. Crawls targets with a real browser, maps the full attack surface, and runs 15 parallel attack modules.

Built for web-category CTF challenges where manual testing is too slow and generic scanners miss JS-heavy apps, SPA logins, and blind injection points.

---

## Features

- **Real browser crawler** — Playwright (Chromium) handles React/Vue/Next.js, executes JavaScript, captures XHR/fetch ghost APIs that static crawlers miss
- **15 attack modules** — SQLi, XSS, LFI, SSTI, SSRF, IDOR, NoSQL, Command Injection, JWT, XXE, File Upload, Open Redirect, Prototype Pollution, GraphQL, DOM XSS
- **Path brute-force** — 151 CTF-focused paths probed in Phase 0 (flag targets, admin panels, backup files, debug endpoints, framework-specific paths); soft-404 filtered
- **JS endpoint mining** — fetches in-scope `.js` bundles and extracts `/api/`, `/rest/`, `/graphql/` paths; HEAD-validates and adds to attack surface
- **CORS misconfiguration detection** — passive check with a spoofed origin; reports wildcard + credentials and reflected-origin patterns
- **Session handoff** — browser login (cookies, JWT, CSRF tokens) is transferred to the HTTP client; works with OAuth2, SPA login flows, DVWA security levels; `--cookie` injects an existing session directly, skipping the login flow entirely
- **OOB callback server** — embedded HTTP listener detects blind SSRF, blind CMDi, and out-of-band SQLi
- **WAF bypass** — 5 tamper techniques (case variation, URL encoding, comment insertion, whitespace, hex encoding) auto-applied on 403/block
- **Dynamic flag detection** — finds flags in JSON values, base64 blobs, HTML comments, response headers, high-entropy strings — not just `FLAG{...}` patterns
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
# Full scan — all 15 modules
python main.py -u https://target.ctf/

# Target specific vectors
python main.py -u https://target.ctf/ --attacks sqli,xss,lfi,cmdi,jwt,graphql,domxss

# Authenticated target (browser handles login, session transferred to scanner)
python main.py -u https://target.ctf/ --login /login --user admin --pass password

# Inject an existing session (no login form needed — grabbed from Burp or browser devtools)
python main.py -u https://target.ctf/ --cookie "PHPSESSID=abc123; security=low"

# Behind Burp Suite proxy
python main.py -u https://target.ctf/ --proxy http://127.0.0.1:8080 --no-verify

# Slow down for sensitive/monitored CTF infra
python main.py -u https://target.ctf/ --rate-limit 3 --delay 0.5 --concurrency 3
```

---

## CTF Workflow

**Step 1 — Quick surface scan**
```bash
python main.py -u https://target.ctf/ --attacks sqli,xss,lfi,ssti,ssrf,cmdi
```
Fast modules first. If a flag drops, stop here.

**Step 2 — Auth-aware scan**
```bash
python main.py -u https://target.ctf/ --login /login --user admin --pass admin \
    --attacks jwt,idor,nosql,upload,graphql,open_redirect,proto_pollution
```
Session-dependent vulnerabilities need a valid login. JWT confusion, IDOR, and upload bypass only surface after auth.

**Step 3 — DOM XSS and full sweep**
```bash
python main.py -u https://target.ctf/ --cookie "SESSION=..." --attacks domxss,xxe,graphql
```
DOM XSS runs a real Chromium instance — use it last since it's the heaviest module. Pass an already-captured session via `--cookie` to skip re-authentication.

**Step 4 — Blind callbacks (needs VPN/tunnel)**
```bash
# OOB server auto-starts with a routable IP — works on HTB/THM VPN out of the box
python main.py -u https://target.ctf/ --attacks sqli,ssrf,cmdi
```
Blind SQLi, blind SSRF, and blind CMDi are reported only when the OOB callback server receives a connection from the target.

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
  [CORS] Reflected origin + credentials @ /api/user

🕷  Phase 1: Active Crawl
  Playwright login complete
  → https://target.ctf/dashboard
  → https://target.ctf/api/v1/users
  → https://target.ctf/api/v1/admin/flag  (ghost API)
  Attack points: 23 | Ghost APIs: 5

⚔  Phase 2: Parallel Attack
  [SQLi]   Error-based hit! Payload: "'"
  [CMDi]   Time-based hit! (3.0s, baseline 0.0s) Payload: '; sleep 3 #'
  [LFI]    File read! Payload: '../../../../etc/passwd'
  [JWT]    RS256→HS256 confusion! Public key used as HMAC secret
  [GraphQL] Introspection enabled — fields: password, token, email
  [DomXSS] alert() fired! payload='<img src=x onerror=alert(...)>'

🚩  Phase 3: Results
╭──────────────────────────┬──────────────────────────────────────┬────────────────╮
│ Type                     │ Value                                │ Confidence     │
├──────────────────────────┼──────────────────────────────────────┼────────────────┤
│ lfi_file_read            │ LFI @ /view ?file → /etc/passwd      │ ████████ 95%   │
│ sqli_error               │ Error-based SQLi @ /search ?q        │ ███████░ 90%   │
│ jwt_rs256_hs256_confusion│ JWT confusion @ /api/me              │ ████████ 95%   │
│ graphql_info_leak        │ Schema exposes: password, token      │ ███████░ 85%   │
│ domxss_execution         │ DOM XSS @ /search ?q                 │ ████████ 95%   │
│ cmdi_time_based          │ CMDi @ /ping ?ip (3.1s)              │ ██████░░ 85%   │
│ cors_reflected_origin    │ CORS wildcard + credentials @ /api   │ ██████░░ 80%   │
╰──────────────────────────┴──────────────────────────────────────┴────────────────╯
```

### Confidence Levels

| Range | Meaning |
|-------|---------|
| 90–95% | Confirmed — payload caused observable, unambiguous effect (flag in response, alert fired, file content returned) |
| 80–89% | Strong — clear behavioral difference; manual verification recommended before reporting |
| 65–79% | Probable — indirect signal (crash signature, timing anomaly, body diff); always verify |
| 50–64% | Weak — endpoint or pattern found, but exploitation not confirmed |

---

## Attack Modules

| Module | Key Signals | Confidence |
|--------|-------------|------------|
| `sqli` | DB error strings, time delay ≥ 2.8s, response length diff ≥ 5%, OOB DNS/HTTP callback | 90% error, 85% time-based, 90% OOB |
| `xss` | Unique marker reflected in response body | 90% |
| `lfi` | `/etc/passwd` content, Windows paths, `/proc/self/environ` in response | 95% |
| `ssti` | `9999×9999 = 99980001` arithmetic result in response | 90% |
| `ssrf` | OOB callback received, internal IP in response, cloud metadata | 85–90% |
| `idor` | Numeric ID swap yields different user data (content + size diff ≥ 20%) | 70% |
| `nosql` | `$gt`, `$ne`, `$where` operators bypass auth or return extra records | 80% |
| `cmdi` | Time delay ≥ 2.8s over baseline, OOB curl/wget callback | 85% |
| `jwt` | alg:none → 200, weak secret verified, RS256→HS256 PEM confusion → 200 | 95% confusion, 90% weak secret |
| `xxe` | File content (`/etc/passwd`, flag file) in XML response | 90% |
| `upload` | Uploaded file executes unique marker payload (RCE confirmed) | 95% |
| `open_redirect` | `Location: https://evil.com` in 3xx response | 85% header, 65% body |
| `proto_pollution` | UUID probe value reflected back in response body | 85% reflected, 65% crash |
| `graphql` | `__schema` in response, sensitive field names in schema, data returned | 75% introspection, 85% info leak |
| `domxss` | `alert()` with unique marker fired in headless Chromium | 95% |

---

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `-u` | required | Target URL |
| `--attacks` | all | Comma-separated module list: `sqli,xss,ssrf,lfi,ssti,idor,nosql,cmdi,jwt,xxe,upload,open_redirect,proto_pollution,graphql,domxss` |
| `--login` | — | Login path (e.g. `/login`) |
| `--user` | — | Username |
| `--pass` | — | Password |
| `--cookie` | — | Existing session cookie string (e.g. `PHPSESSID=abc123; token=xyz`) |
| `--proxy` | — | HTTP proxy URL (e.g. `http://127.0.0.1:8080`) |
| `--no-verify` | false | Disable TLS certificate verification |
| `--rate-limit` | 5.0 | Max requests per second (token bucket) |
| `--delay` | 0.0 | Fixed delay between requests (seconds) |
| `--concurrency` | 5 | Max concurrent HTTP connections |
| `--max-pages` | 50 | Max pages crawled by Playwright |

---

## Architecture

### Execution Flow

```
Phase 0  Passive recon    151 paths probed (paths.txt + built-ins): robots.txt, .git, admin panels,
                          backup files, phpinfo, framework endpoints; soft-404 filtered.
                          CORS misconfiguration check runs here (spoofed Origin header).
Phase 1  Active crawl     Playwright navigates pages, captures forms + XHR ghost APIs.
                          JS bundle mining extracts /api/ and /rest/ paths from .js files.
Phase 2  Parallel attack  asyncio.gather runs all 15 modules concurrently per attack point.
Phase 3  Results          CORS findings prepended, all findings ranked by confidence, printed.
```

### Session Handoff

After Playwright login, `session_bridge.py` extracts cookies, JWT tokens (from localStorage, sessionStorage, cookies), and CSRF tokens from the live DOM. These are transferred to an `httpx.AsyncClient`, so every attack request carries the same authenticated state the browser established — including security-level cookies (e.g. DVWA's `security=low`).

If a session already exists (e.g. captured from Burp or a previous login), `--cookie "NAME=val; NAME2=val2"` injects it directly into both the Playwright browser context and the httpx client before the crawl begins. Cookies established by the login flow take priority over manually injected ones if the same name appears in both.

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

An `aiohttp` TCP site binds on `0.0.0.0:9999` and auto-detects the machine's routable IP. SSRF, CMDi, and OOB SQLi payloads inject `curl`/`wget`/DNS callbacks to this URL. If the target makes an outbound connection, the source IP and timestamp are logged — confirming blind execution without relying on response content.

### JWT Module

Uses Python stdlib (`base64`, `hmac`, `hashlib`) plus `cryptography` for RS256 key parsing. Performs four attacks in sequence:

1. **alg:none bypass** — three case variants (`none`, `None`, `NONE`) since some implementations are case-sensitive
2. **Weak secret brute-force** — CPU-only HMAC comparison against 30 common secrets; no network requests during brute-force
3. **Privilege escalation** — rewrites `role`, `is_admin`, `admin`, `group`, `sub` claims if a working signing method is found
4. **RS256→HS256 confusion** — fetches JWKS from 7 paths in parallel (3 s timeout each, ~6 s total), converts RSA public key to PEM bytes, uses them directly as the HMAC-SHA256 secret

A protected endpoint is identified by confirming that a valid token returns 200 and a garbage token returns 401/403 — preventing false positives on public endpoints.

### DOM XSS Module

Uses a singleton Playwright browser (launched once, shared across all `run()` calls) to keep overhead low. Each invocation opens its own browser context (separate cookies, storage, network state) and closes it when done — preventing cross-test contamination and memory leaks.

A semaphore (`Semaphore(3)`) caps concurrent contexts at three. Acquire has a 20-second timeout: if the browser is saturated and a slot doesn't free in time, the test point is skipped rather than queuing indefinitely. This prevents a browser crash from cascading to all waiting tasks.

If the browser process dies mid-scan, `_get_browser()` detects the disconnected state via `is_connected()`, tears down the stale instance, and relaunches — transparently to the calling code.

---

## Notes

- Designed for **CTF web challenges** — not for use on systems without explicit authorization
- OOB callbacks require a **routable IP** (CTF VPN, HTB/THM tunnel, or your lab's network interface)
- JWT RS256→HS256 confusion requires `cryptography>=41.0` (included in `requirements.txt`)
- Prototype pollution targets Node.js/Express apps — Java/Python backends are unaffected
- DOM XSS only tests GET parameters — POST body injection is not evaluated by the browser
- NoSQL module targets MongoDB operator patterns; other NoSQL engines may need custom payloads

---

## Troubleshooting

**OOB callbacks not arriving**
The OOB server needs a routable IP. Check with `ip a` — if your interface is `127.x.x.x` only, connect to the CTF VPN first. On HTB/THM this is `tun0`.

**DOM XSS: browser crashes after many pages**
The singleton browser can die under heavy load. T-Web auto-detects the crash via `is_connected()` and relaunches on the next invocation. If you see repeated `Browser başlatılamadı` messages, reduce concurrency: `--concurrency 2`.

**WAF blocking payloads**
T-Web applies 5 tamper strategies automatically on 403 responses. If all are blocked, route through Burp (`--proxy http://127.0.0.1:8080`) and observe which tamper is closest to bypassing — then craft manually from there.

**JWT: RS256→HS256 returns None**
Ensure the target exposes a JWKS endpoint. T-Web checks 7 common paths. If none return a valid JWK, the attack is skipped. Use Burp to find the actual JWKS URL and probe it manually.

**Upload module: no RCE finding despite 200 response**
The module only reports after the uploaded file executes a unique marker. If the server saves the file but the upload directory is not web-accessible, execution confirmation fails and no finding is generated — correct behavior, not a bug.

---

## Author

Tajaa
