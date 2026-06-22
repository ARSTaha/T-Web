"""
Open Redirect attack module.
Detects unvalidated redirect vulnerabilities via Location header and body analysis.
"""
from __future__ import annotations
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs

from attacks.base import BaseAttack, SessionExpiredError
from rich.console import Console

console = Console(legacy_windows=False)

REDIRECT_PARAMS = {
    "to", "url", "redirect", "next", "return", "returnurl", "redirect_uri",
    "callback", "destination", "goto", "link", "target", "forward", "redir",
    "redirectto", "return_url", "successurl", "ref", "back",
    "location", "continue", "out", "view", "path",
}

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https:evil.com",
    "\\/\\/evil.com",
]

_EVIL_HOST = "evil.com"


class OpenRedirectAttack(BaseAttack):
    name = "open_redirect"

    def _is_relevant(self, attack_point: dict) -> bool:
        param = (attack_point.get("param") or "").lower()
        return param in REDIRECT_PARAMS

    def _inject_url(self, base_url: str, param: str, payload: str) -> str:
        parsed = urlparse(base_url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [payload]
        new_query = urlencode(qs, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    async def run(self, attack_point: dict, _payloads: list[str]) -> list[dict]:
        if not self._is_relevant(attack_point):
            return []

        url = attack_point["url"]
        param = attack_point["param"]
        method = attack_point.get("method", "GET")

        console.print(f"  [cyan][Redirect][/cyan] {method} {url} ?{param}")

        all_findings: list[dict] = []

        for payload in REDIRECT_PAYLOADS:
            if self._should_stop():
                return all_findings

            try:
                if method == "POST":
                    extra = dict(attack_point.get("extra_data") or {})
                    extra[param] = payload
                    resp = await self.session.post(
                        url,
                        data={k: str(v) for k, v in extra.items()},
                        follow_redirects=False,
                        timeout=10.0,
                    )
                else:
                    injected = self._inject_url(url, param, payload)
                    resp = await self.session.get(
                        injected,
                        follow_redirects=False,
                        timeout=10.0,
                    )
            except SessionExpiredError:
                raise
            except Exception:
                continue

            if resp is None:
                continue

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location", "")
                if _EVIL_HOST in location:
                    console.print(
                        f"  [bold red][Redirect][/bold red] Open redirect! "
                        f"Location: {location!r} payload={payload!r}"
                    )
                    all_findings.append({
                        "type": "open_redirect",
                        "value": (
                            f"Open redirect @ {url} ?{param}={payload!r} "
                            f"→ Location: {location}"
                        ),
                        "confidence": 0.85,
                    })
                    return all_findings

            # Body-only signal: some frameworks embed redirect target in HTML
            body = resp.text or ""
            if _EVIL_HOST in body and resp.status_code in (200, 302):
                console.print(
                    f"  [bold yellow][Redirect][/bold yellow] Redirect in body! payload={payload!r}"
                )
                all_findings.append({
                    "type": "open_redirect",
                    "value": (
                        f"Open redirect (body) @ {url} ?{param}={payload!r}"
                    ),
                    "confidence": 0.65,
                })
                return all_findings

        return all_findings
