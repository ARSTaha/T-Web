"""
Playwright-based crawler with ghost API capture.
- 100% async (from playwright.async_api)
- Static resources aborted (no CSS/img/font through the browser)
- Scope-aware (no external URLs)
- Logout/delete URL blacklist
- Memory-safe batch crawling (PAGES_PER_CONTEXT limit)
- domcontentloaded + 2s sleep (no networkidle deadlock)
"""
from __future__ import annotations
import asyncio
import json
import re
from urllib.parse import urlparse, urljoin, urlencode, parse_qs, urlunparse

from playwright.async_api import async_playwright, Browser, BrowserContext, Page
from rich.console import Console
from engine.session_bridge import extract_session, get_init_script

console = Console()

PAGES_PER_CONTEXT = 20

STATIC_RESOURCE_PATTERNS = [
    "**/*.{png,jpg,jpeg,gif,svg,webp,ico,bmp}",
    "**/*.{css,woff,woff2,ttf,eot,otf}",
    "**/*.{mp4,mp3,wav,ogg,avi,mov}",
    "**/*.{pdf,zip,rar,gz,tar}",
]

ANALYTICS_PATTERNS = [
    "**/analytics*",
    "**/gtag*",
    "**/google-analytics*",
    "**/*.googlesyndication.*",
    "**/hotjar*",
    "**/facebook.net/**",
]

DANGEROUS_PATH_PATTERNS = [
    "/logout", "/signout", "/sign-out", "/log-out",
    "/delete", "/remove", "/destroy",
    "/reset-password", "/reset",
    "/clear", "/flush",
    "/api/user/delete", "/api/session/destroy",
    "/account/delete", "/profile/delete",
]

TECH_FINGERPRINTS = {
    "Next.js": ["_next/", "__NEXT_DATA__", "next.js"],
    "React": ["react.development.js", "react.production.min.js", "__reactFiber"],
    "Vue.js": ["__vue__", "vue.runtime", "nuxt"],
    "Angular": ["ng-version", "angular.js", "ng-app"],
    "Django": ["csrfmiddlewaretoken", "django", "djdt"],
    "Laravel": ["laravel_session", "XSRF-TOKEN"],
    "Express": ["X-Powered-By: Express"],
    "Spring": ["JSESSIONID", "org.springframework"],
    "Flask": ["werkzeug", "flask"],
    "PHP": ["PHPSESSID", "X-Powered-By: PHP"],
    "WordPress": ["wp-content", "wp-json", "wordpress"],
    "GraphQL": ["/graphql", "__typename", "GraphQL"],
}


def _get_target_netloc(start_url: str) -> str:
    return urlparse(start_url).netloc


def _is_in_scope(url: str, target_netloc: str) -> bool:
    parsed = urlparse(url)
    netloc = parsed.netloc
    if netloc == "":
        return True
    if netloc == target_netloc:
        return True
    target_host = target_netloc.split(":")[0]
    current_host = netloc.split(":")[0]
    is_ip = bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", target_host))
    if not is_ip and current_host.endswith("." + target_host):
        return True
    return False


def _is_safe_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    return not any(pattern in path for pattern in DANGEROUS_PATH_PATTERNS)


def _detect_tech(headers: dict, body: str) -> list[str]:
    detected = []
    combined = str(headers) + " " + body
    for tech, signals in TECH_FINGERPRINTS.items():
        if any(s.lower() in combined.lower() for s in signals):
            detected.append(tech)
    return detected


async def _setup_context(browser: Browser, stealth: bool = True) -> BrowserContext:
    context = await browser.new_context(
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/125.0.0.0 Safari/537.36"
        ),
        locale="tr-TR",
        timezone_id="Europe/Istanbul",
        viewport={"width": 1920, "height": 1080},
    )
    if stealth:
        await context.add_init_script(
            "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
        )
    return context


async def _block_static(page: Page):
    for pattern in STATIC_RESOURCE_PATTERNS + ANALYTICS_PATTERNS:
        await page.route(pattern, lambda r: r.abort())


async def _crawl_page(page: Page, url: str, target_netloc: str = "") -> dict:
    captured_requests = []
    response_headers = {}

    def on_request(request):
        if request.resource_type in ("xhr", "fetch", "websocket"):
            captured_requests.append({
                "url": request.url,
                "method": request.method,
                "post_data": request.post_data,
            })

    def on_response(response):
        nonlocal response_headers
        if response.url == url or response.url.rstrip("/") == url.rstrip("/"):
            response_headers = dict(response.headers)

    page.on("request", on_request)
    page.on("response", on_response)

    try:
        await page.goto(url, wait_until="domcontentloaded", timeout=15000)
        await asyncio.sleep(2.0)
    except Exception as e:
        console.print(f"[dim]  [!] {url} yüklenemedi: {e}[/dim]")
        return {}

    # If a redirect sent us to an external domain, don't extract any data from it.
    # This prevents forms/links from github.com (or other redirect targets) leaking
    # into attack_points as if they were in-scope endpoints.
    if target_netloc and not _is_in_scope(page.url, target_netloc):
        return {}

    try:
        forms = await page.evaluate("""() =>
            Array.from(document.forms).map(f => ({
                action: f.action,
                method: f.method || 'GET',
                inputs: Array.from(f.elements)
                    .filter(e => e.name)
                    .map(e => ({name: e.name, type: e.type, value: e.value || e.defaultValue || ''}))
            }))
        """)
    except Exception:
        forms = []

    try:
        links = await page.eval_on_selector_all(
            "a[href]", "els => els.map(e => e.href)"
        )
    except Exception:
        links = []

    try:
        page_title = await page.title()
    except Exception:
        page_title = ""

    try:
        body_html = await page.content()
    except Exception:
        body_html = ""

    return {
        "url": url,
        "title": page_title,
        "forms": forms,
        "links": links,
        "ghost_apis": captured_requests,
        "response_headers": response_headers,
        "body_snippet": body_html[:3000],
    }


async def run_recon(
    start_url: str,
    max_pages: int = 50,
    login_url: str | None = None,
    username: str | None = None,
    password: str | None = None,
) -> dict:
    console.print(f"  [cyan]Hedef:[/cyan] {start_url}")
    target_netloc = _get_target_netloc(start_url)

    all_pages_data = []
    visited = set()
    to_visit = [start_url]
    tech_stack = []
    all_attack_points = []
    all_ghost_apis = []

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True,
            args=["--disable-blink-features=AutomationControlled", "--no-sandbox"],
        )

        page_count = 0
        context = await _setup_context(browser)
        _saved_local_storage: dict = {}

        # Playwright ile login — kimlik bilgileri varsa crawl öncesi oturum aç
        if login_url and username and password:
            try:
                login_page = await context.new_page()
                await _block_static(login_page)
                await login_page.goto(login_url, wait_until="domcontentloaded", timeout=15000)
                await asyncio.sleep(1.0)

                # Kullanıcı adı alanını doldur
                for sel in ["[name=username]", "[name=email]", "[name=user]", "[name=login]", "[type=text]"]:
                    try:
                        await login_page.fill(sel, username, timeout=2000)
                        break
                    except Exception:
                        continue

                # Şifre alanını doldur
                for sel in ["[name=password]", "[name=pass]", "[name=passwd]", "[type=password]"]:
                    try:
                        await login_page.fill(sel, password, timeout=2000)
                        break
                    except Exception:
                        continue

                # Formu gönder
                for sel in ["[type=submit]", "[name=Login]", "[name=submit]", "button[type=submit]", "button"]:
                    try:
                        await login_page.click(sel, timeout=2000)
                        break
                    except Exception:
                        continue

                await asyncio.sleep(2.0)
                console.print(f"  [green]Playwright login tamamlandı[/green]")
                await login_page.close()
            except Exception as e:
                console.print(f"  [yellow]Playwright login başarısız: {e}[/yellow]")

        while to_visit and page_count < max_pages:
            batch_urls = []
            while to_visit and len(batch_urls) < PAGES_PER_CONTEXT:
                url = to_visit.pop(0)
                if url not in visited and _is_in_scope(url, target_netloc) and _is_safe_url(url):
                    visited.add(url)
                    batch_urls.append(url)

            if not batch_urls:
                break

            if page_count > 0 and page_count % PAGES_PER_CONTEXT == 0:
                # Save cookies + localStorage before closing so session survives renewal
                _saved_cookies_ctx: list = []
                try:
                    _ls_page = await context.new_page()
                    _ls_raw = await _ls_page.evaluate("() => JSON.stringify(localStorage)")
                    if _ls_raw:
                        _saved_local_storage = json.loads(_ls_raw)
                    await _ls_page.close()
                    _saved_cookies_ctx = await context.cookies()
                except Exception:
                    pass
                await context.close()
                context = await _setup_context(browser)
                if _saved_cookies_ctx:
                    await context.add_cookies(_saved_cookies_ctx)
                if _saved_local_storage:
                    await context.add_init_script(get_init_script(_saved_local_storage))
                console.print(f"  [dim]Context yenilendi (RAM temizlendi)[/dim]")

            for url in batch_urls:
                page = await context.new_page()
                await _block_static(page)
                console.print(f"  [dim]→ {url}[/dim]")

                data = await _crawl_page(page, url, target_netloc)
                await page.close()

                if not data:
                    continue

                all_pages_data.append(data)
                page_count += 1

                # Crawlanan URL'nin kendi query parametrelerini attack point olarak ekle
                current_parsed = urlparse(url)
                if current_parsed.query:
                    for param_kv in current_parsed.query.split("&"):
                        key = param_kv.split("=")[0]
                        if key:
                            all_attack_points.append({
                                "type": "url_param",
                                "url": url,
                                "method": "GET",
                                "param": key,
                            })

                tech = _detect_tech(data.get("response_headers", {}), data.get("body_snippet", ""))
                for t in tech:
                    if t not in tech_stack:
                        tech_stack.append(t)

                for form in data.get("forms", []):
                    action = form.get("action") or url
                    method = form.get("method", "GET").upper()
                    inputs = form.get("inputs", [])
                    form_defaults = {
                        inp["name"]: inp.get("value", "")
                        for inp in inputs if inp.get("name")
                    }
                    attack_action = action
                    if method == "GET" and form_defaults:
                        _pa = urlparse(action)
                        _existing = {k: v[0] for k, v in parse_qs(_pa.query).items()}
                        _merged = {**form_defaults, **_existing}
                        attack_action = urlunparse(_pa._replace(query=urlencode(_merged)))
                    for inp in inputs:
                        name = inp.get("name")
                        if not name or inp.get("type") in ("submit", "button", "image", "reset"):
                            continue
                        all_attack_points.append({
                            "type": "form_input",
                            "url": attack_action,
                            "method": method,
                            "param": name,
                            "input_type": inp.get("type", "text"),
                        })

                for link in data.get("links", []):
                    abs_link = urljoin(url, link)
                    if _is_in_scope(abs_link, target_netloc):
                        parsed = urlparse(abs_link)
                        if parsed.query:
                            for param in parsed.query.split("&"):
                                key = param.split("=")[0]
                                if key:
                                    all_attack_points.append({
                                        "type": "url_param",
                                        "url": abs_link,
                                        "method": "GET",
                                        "param": key,
                                    })
                    if abs_link not in visited:
                        to_visit.append(abs_link)

                for api in data.get("ghost_apis", []):
                    api_url = api.get("url", "")
                    if not _is_in_scope(api_url, target_netloc):
                        continue
                    all_ghost_apis.append(api)
                    api_method = api.get("method", "GET").upper()
                    api_parsed = urlparse(api_url)
                    if api_parsed.query:
                        # Extract each query param so attack modules can inject into them
                        for param_kv in api_parsed.query.split("&"):
                            key_part = param_kv.split("=")[0]
                            if key_part:
                                all_attack_points.append({
                                    "type": "api_param",
                                    "url": api_url,
                                    "method": api_method,
                                    "param": key_part,
                                    "post_data": api.get("post_data"),
                                })
                    else:
                        # Parameterless endpoint — keep for NoSQL POST body injection
                        all_attack_points.append({
                            "type": "api_endpoint",
                            "url": api_url,
                            "method": api_method,
                            "param": None,
                            "post_data": api.get("post_data"),
                        })

        # Extract session from last context before closing (best-effort)
        extracted_session: dict = {
            "cookies": [], "jwt": None, "csrf": None,
            "local_storage": {}, "session_storage": {},
        }
        try:
            _sess_page = await context.new_page()
            _resp_headers: dict = {}

            def _capture_headers(response):
                nonlocal _resp_headers
                if response.url.rstrip("/") == start_url.rstrip("/"):
                    _resp_headers = dict(response.headers)

            _sess_page.on("response", _capture_headers)
            await _sess_page.goto(start_url, wait_until="domcontentloaded", timeout=10000)
            extracted_session = await extract_session(_sess_page, _resp_headers)
            await _sess_page.close()
        except Exception:
            pass

        await context.close()
        await browser.close()

    deduped_points = []
    seen_points = set()
    for ap in all_attack_points:
        # Dedup by path (not full URL) + param + method so fi/?page=file1.php and
        # fi/?page=file2.php don't produce separate attack points for the same param
        _ap_path = urlparse(ap["url"]).path
        key = (_ap_path, ap.get("param"), ap["method"])
        if key not in seen_points:
            seen_points.add(key)
            deduped_points.append(ap)

    interesting_headers = {}
    for pd in all_pages_data:
        for k, v in pd.get("response_headers", {}).items():
            if k.lower() in ("x-powered-by", "server", "x-frame-options", "x-aspnet-version"):
                interesting_headers[k] = v

    notes = []
    if any("admin" in p.get("url", "").lower() for p in deduped_points):
        notes.append("Admin panel endpoint tespit edildi")
    if any("graphql" in p.get("url", "").lower() for p in deduped_points):
        notes.append("GraphQL endpoint bulundu — introspection dene")

    return {
        "start_url": start_url,
        "pages_crawled": page_count,
        "tech_stack": tech_stack,
        "attack_points": deduped_points[:100],
        "ghost_apis": all_ghost_apis[:50],
        "interesting_headers": interesting_headers,
        "notes": notes,
        "session_data": extracted_session,
    }
