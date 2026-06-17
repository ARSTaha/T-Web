"""
Session handoff from Playwright (Chromium) to httpx.
Extracts: cookies, JWT (regex scan of all storages), CSRF token (3 sources).
Returns a dict that build_httpx_session() can consume.
"""
from __future__ import annotations
import json
import re

import httpx
from playwright.async_api import Page

JWT_REGEX = r"ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"

DANGEROUS_PATH_PATTERNS = [
    "/logout", "/signout", "/sign-out", "/log-out",
    "/delete", "/remove", "/destroy",
    "/reset", "/clear", "/flush",
    "/api/user/delete", "/api/session/destroy",
]


async def extract_session(page: Page, response_headers: dict | None = None) -> dict:
    cookies = await page.context.cookies()

    local_storage_raw = await page.evaluate("() => JSON.stringify(localStorage)")
    session_storage_raw = await page.evaluate("() => JSON.stringify(sessionStorage)")

    local_storage = json.loads(local_storage_raw) if local_storage_raw else {}
    session_storage = json.loads(session_storage_raw) if session_storage_raw else {}

    jwt = None
    for raw in [local_storage_raw, session_storage_raw]:
        if raw:
            matches = re.findall(JWT_REGEX, raw)
            if matches:
                jwt = matches[0]
                break

    if jwt is None:
        for c in cookies:
            if re.match(JWT_REGEX, c.get("value", "")):
                jwt = c["value"]
                break

    csrf = await page.evaluate("""() => {
        const input = document.querySelector(
            '[name=csrf_token],[name=_csrf],[name=__RequestVerificationToken],[name=authenticity_token]'
        );
        if (input) return input.value;
        const meta = document.querySelector('meta[name="csrf-token"],meta[name="_csrf"]');
        if (meta) return meta.getAttribute('content');
        return null;
    }""")

    # 3rd CSRF source: response headers (X-CSRF-Token, X-CSRFToken, csrf-token)
    if csrf is None and response_headers:
        for header_name in ("x-csrf-token", "x-csrftoken", "csrf-token", "x-xsrf-token"):
            csrf = response_headers.get(header_name)
            if csrf:
                break

    return {
        "cookies": cookies,
        "jwt": jwt,
        "csrf": csrf,
        "local_storage": local_storage,
        "session_storage": session_storage,
    }


def build_httpx_session(
    session_data: dict,
    proxy: str | None = None,
    no_verify: bool = False,
) -> httpx.AsyncClient:
    cookie_jar = {c["name"]: c["value"] for c in session_data.get("cookies", [])}
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/125.0.0.0 Safari/537.36"
        )
    }
    if session_data.get("jwt"):
        headers["Authorization"] = f"Bearer {session_data['jwt']}"
    if session_data.get("csrf"):
        headers["X-CSRF-Token"] = session_data["csrf"]
        headers["X-CSRFToken"] = session_data["csrf"]

    return httpx.AsyncClient(
        cookies=cookie_jar,
        headers=headers,
        proxy=proxy,
        verify=not no_verify,
        follow_redirects=True,
        timeout=httpx.Timeout(15.0),
    )


def get_init_script(local_storage: dict) -> str:
    ls_json = json.dumps(local_storage)
    return f"""
        (function() {{
            const data = {ls_json};
            for (const [key, value] of Object.entries(data)) {{
                try {{ localStorage.setItem(key, value); }} catch(e) {{}}
            }}
        }})();
    """
