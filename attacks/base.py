"""
Base attack class with SessionManager (asyncio.Event based, deadlock-free).
All attack modules inherit from BaseAttack and use self.session for requests.
"""
from __future__ import annotations
import asyncio
import httpx
from rich.console import Console
from engine.flag_hunter import extract_interesting_data

console = Console()


class SessionExpiredError(Exception):
    pass


class SessionManager:
    def __init__(self, client: httpx.AsyncClient):
        self._client = client
        self._healthy = asyncio.Event()
        self._healthy.set()

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        await self._healthy.wait()
        try:
            response = await self._client.request(method, url, **kwargs)
        except httpx.TimeoutException:
            raise
        except Exception:
            raise

        if response.status_code == 401:
            self._healthy.clear()
            raise SessionExpiredError(
                f"Session expired (401) at {url}. "
                "Re-auth gerekiyor."
            )
        return response

    async def get(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    def restore(self, new_client: httpx.AsyncClient):
        self._client = new_client
        self._healthy.set()

    async def aclose(self):
        await self._client.aclose()


class BaseAttack:
    name = "base"

    def __init__(
        self,
        session: SessionManager,
        oob_server=None,
        stop_event: asyncio.Event | None = None,
    ):
        self.session = session
        self.oob = oob_server
        self.stop_event = stop_event or asyncio.Event()
        self.findings: list[dict] = []

    def _should_stop(self) -> bool:
        return self.stop_event.is_set()

    async def _try_payload(
        self,
        method: str,
        url: str,
        param: str | None,
        payload: str,
        data: dict | None = None,
        json_data: dict | None = None,
        as_header: bool = False,
    ) -> tuple[httpx.Response | None, list[dict]]:
        if self._should_stop():
            return None, []
        try:
            if as_header and param:
                # httpx rejects header values with trailing whitespace (e.g. "-- ").
                # Strip it — MySQL recognizes "--" at end-of-query without trailing space.
                header_payload = payload.rstrip()
                if not header_payload:
                    return None, []
                try:
                    response = await self.session.request(
                        method, url, headers={param: header_payload}, timeout=10.0
                    )
                except ValueError:
                    return None, []  # silently skip — other chars httpx rejects
            elif method.upper() == "GET" and param:
                from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                params[param] = [payload]
                new_query = urlencode(params, doseq=True)
                target_url = urlunparse(parsed._replace(query=new_query))
                response = await self.session.get(target_url, timeout=10.0)
            elif method.upper() == "POST":
                post_data = dict(data or {})
                if param:
                    post_data[param] = payload
                if json_data:
                    jd = dict(json_data)
                    if param:
                        jd[param] = payload
                    response = await self.session.post(url, json=jd, timeout=10.0)
                else:
                    response = await self.session.post(url, data=post_data, timeout=10.0)
            else:
                response = await self.session.get(url, timeout=10.0)

            findings = extract_interesting_data(response.text)
            return response, findings

        except SessionExpiredError:
            raise
        except Exception as e:
            if str(e):  # suppress blank messages (e.g. bare asyncio.TimeoutError)
                console.print(f"  [dim][!] {self.name}: {url} → {e}[/dim]")
            return None, []

    async def run(self, attack_point: dict, payloads: list[str]) -> list[dict]:
        raise NotImplementedError
