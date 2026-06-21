"""
Rate-limited async HTTP client with Burp Suite proxy support.
Token bucket pattern: lock is held briefly for timestamp update only,
sleep happens outside the lock so coroutines can wait concurrently.
"""
from __future__ import annotations
import asyncio
import httpx
from rich.console import Console

console = Console(legacy_windows=False)


class RateLimitedClient:
    def __init__(
        self,
        client: httpx.AsyncClient,
        rate_per_sec: float = 5.0,
        concurrency: int = 5,
        min_delay: float = 0.0,
    ):
        self._client = client
        self._semaphore = asyncio.Semaphore(concurrency)
        # min_delay overrides rate_per_sec if it enforces a longer interval
        self._min_interval = max(1.0 / rate_per_sec, min_delay)
        self._last_request_time = 0.0
        self._time_lock = asyncio.Lock()
        self._consecutive_errors = 0
        self._current_rate = rate_per_sec

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        async with self._time_lock:
            loop = asyncio.get_running_loop()
            now = loop.time()
            wait_time = max(0.0, self._min_interval - (now - self._last_request_time))
            self._last_request_time = now + wait_time

        if wait_time > 0:
            await asyncio.sleep(wait_time)

        async with self._semaphore:
            try:
                response = await self._client.request(method, url, **kwargs)
            except Exception as e:
                self._consecutive_errors += 1
                if self._consecutive_errors >= 5:
                    console.print(
                        f"[red][!] 5 ardışık hata. Sunucu yavaşlıyor olabilir. "
                        f"--rate-limit azaltmayı dene.[/]"
                    )
                raise

            if response.status_code == 429:
                self._current_rate = max(1.0, self._current_rate / 2)
                self._min_interval = 1.0 / self._current_rate
                console.print(
                    f"[yellow][!] 429 Too Many Requests → rate {self._current_rate:.1f} req/s'e düşürüldü. "
                    f"3s bekleniyor...[/]"
                )
                await asyncio.sleep(3.0)

            self._consecutive_errors = 0
            return response

    async def get(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def aclose(self):
        await self._client.aclose()


def build_client(
    proxy: str | None = None,
    no_verify: bool = False,
    rate_per_sec: float = 5.0,
    concurrency: int = 5,
    min_delay: float = 0.0,
    headers: dict | None = None,
    cookies: dict | None = None,
) -> RateLimitedClient:
    if proxy and not no_verify:
        console.print(
            "[yellow]⚠  Burp proxy + SSL verify açık. "
            "Cert hatası alırsan --no-verify ekle.[/]"
        )

    base_headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/125.0.0.0 Safari/537.36"
        )
    }
    if headers:
        base_headers.update(headers)

    client = httpx.AsyncClient(
        proxy=proxy,
        verify=not no_verify,
        headers=base_headers,
        cookies=cookies or {},
        follow_redirects=True,
        timeout=httpx.Timeout(15.0),
    )
    return RateLimitedClient(client, rate_per_sec=rate_per_sec, concurrency=concurrency, min_delay=min_delay)
