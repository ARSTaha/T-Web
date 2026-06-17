"""
Flag detection engine.
Combines known pattern matching with interesting data extraction.
Scores each finding — high-confidence ones are shown prominently,
lower-confidence ones are shown in a table for user inspection.
"""
from __future__ import annotations
import base64
import ipaddress
import json
import re

FLAG_PATTERNS = [
    r"SiberVatan\{[^}]+\}",
    r"CTF\{[^}]+\}",
    r"FLAG\{[^}]+\}",
    r"flag\{[^}]+\}",
    r"HTB\{[^}]+\}",
    r"picoCTF\{[^}]+\}",
    r"DUCTF\{[^}]+\}",
    r"LITCTF\{[^}]+\}",
    r"BYUCTF\{[^}]+\}",
]

INTERESTING_JSON_KEYS = [
    "password", "passwd", "secret", "token", "flag", "key",
    "api_key", "private", "credentials", "hash", "admin_pass",
    "access_token", "refresh_token", "auth_token",
]

WEBPACK_HASH_RE = re.compile(r"^[a-f0-9]{20,64}$")


def _find_key_recursive(obj, target_key: str, depth: int = 0):
    if depth > 10:
        return None
    if isinstance(obj, dict):
        if target_key in obj:
            return obj[target_key]
        for v in obj.values():
            result = _find_key_recursive(v, target_key, depth + 1)
            if result is not None:
                return result
    elif isinstance(obj, list):
        for item in obj:
            result = _find_key_recursive(item, target_key, depth + 1)
            if result is not None:
                return result
    return None


def extract_interesting_data(response_text: str) -> list[dict]:
    findings: list[dict] = []

    for pat in FLAG_PATTERNS:
        for m in re.finditer(pat, response_text, re.IGNORECASE):
            findings.append({"type": "flag_format", "value": m.group(), "confidence": 1.0})

    try:
        data = json.loads(response_text)
        for key in INTERESTING_JSON_KEYS:
            val = _find_key_recursive(data, key)
            if val and isinstance(val, str) and len(val) > 1:
                findings.append({
                    "type": f"json_key:{key}",
                    "value": str(val),
                    "confidence": 0.8,
                })
    except (json.JSONDecodeError, TypeError):
        pass

    for ip_str in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", response_text):
        try:
            ipaddress.ip_address(ip_str)
            findings.append({"type": "ip_address", "value": ip_str, "confidence": 0.6})
        except ValueError:
            pass

    for comment in re.findall(r"<!--(.*?)-->", response_text, re.DOTALL):
        stripped = comment.strip()
        if len(stripped) > 3:
            findings.append({"type": "html_comment", "value": stripped[:200], "confidence": 0.5})

    if len(response_text) < 200_000:
        for candidate in re.findall(r"[A-Za-z0-9+/]{32,128}={0,2}", response_text):
            if WEBPACK_HASH_RE.match(candidate):
                continue
            try:
                padding = -len(candidate) % 4
                decoded = base64.b64decode(candidate + "=" * padding).decode("utf-8", errors="ignore")
                for pat in FLAG_PATTERNS:
                    if re.search(pat, decoded, re.IGNORECASE):
                        findings.append({
                            "type": "base64_decoded_flag",
                            "value": decoded[:200],
                            "confidence": 0.95,
                        })
                        break
                else:
                    printable_ratio = sum(c.isprintable() for c in decoded) / max(len(decoded), 1)
                    if printable_ratio > 0.9 and 8 < len(decoded) < 200:
                        findings.append({
                            "type": "high_entropy_b64",
                            "value": decoded[:100],
                            "confidence": 0.3,
                        })
            except Exception:
                pass

    seen = set()
    deduped = []
    for f in findings:
        key = (f["type"], f["value"])
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    return sorted(deduped, key=lambda x: x["confidence"], reverse=True)


def has_definite_flag(findings: list[dict]) -> str | None:
    for f in findings:
        if f["confidence"] >= 1.0:
            return f["value"]
    return None
