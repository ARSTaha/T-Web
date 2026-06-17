"""
Out-of-Band callback server for detecting blind vulnerabilities.
Token is embedded in the URL PATH (not query string) to survive SSRF filters.

Usage:
    oob = OOBServer()
    url = await oob.start()          # "http://192.168.1.10:9999"
    token = oob.generate_token("ssrf")
    payload = f"{url}/{token}"       # embed in SSRF/Blind SQLi/XXE payload
    ...
    if oob.was_triggered(token):     # True → blind vuln confirmed
"""
from __future__ import annotations
import asyncio
import socket
import uuid
from aiohttp import web


class OOBServer:
    def __init__(self):
        self.hits: dict[str, dict] = {}
        self._runner: web.AppRunner | None = None
        self.public_url: str = ""

    async def start(self, port: int = 9999) -> str:
        app = web.Application()
        app.router.add_get("/{token}", self._handle_hit)
        app.router.add_get("/{token}/{extra:.*}", self._handle_hit)

        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "0.0.0.0", port)
        await site.start()

        self.public_url = self._get_local_ip(port)
        return self.public_url

    async def stop(self):
        if self._runner:
            await self._runner.cleanup()

    def _get_local_ip(self, port: int) -> str:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        except Exception:
            local_ip = "127.0.0.1"
        finally:
            s.close()
        return f"http://{local_ip}:{port}"

    def generate_token(self, vector: str) -> str:
        token = str(uuid.uuid4())[:8]
        self.hits[token] = {"vector": vector, "triggered": False, "source_ip": None}
        return token

    async def _handle_hit(self, request: web.Request) -> web.Response:
        token = request.match_info.get("token", "")
        if token in self.hits:
            self.hits[token]["triggered"] = True
            self.hits[token]["source_ip"] = request.remote
        return web.Response(text="ok")

    def was_triggered(self, token: str) -> bool:
        return self.hits.get(token, {}).get("triggered", False)

    def get_hit_info(self, token: str) -> dict:
        return self.hits.get(token, {})
