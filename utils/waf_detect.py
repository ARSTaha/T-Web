"""
WAF detection and basic bypass helpers.
"""
from __future__ import annotations
import re

WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cloudflare", "__cfduid", "cf-cache-status"],
    "AWS WAF": ["x-amzn-requestid", "x-amzn-trace-id", "x-amz-cf-id"],
    "ModSecurity": ["mod_security", "modsecurity", "NOYB"],
    "Akamai": ["akamai", "ak-bmsc", "bm_sz"],
    "Imperva": ["incap_ses", "visid_incap", "X-Iinfo"],
    "Sucuri": ["x-sucuri-id", "sucuri/cloudproxy"],
    "F5 BIG-IP": ["bigipserver", "f5-asm", "TS01"],
    "Nginx WAF": ["nginx", "naxsi"],
}

WAF_STATUS_CODES = {403, 406, 429, 503}

TAMPER_FUNCTIONS = {
    "space2comment": lambda p: p.replace(" ", "/**/"),
    "url_encode": lambda p: "".join(f"%{ord(c):02X}" if c in "' \"=" else c for c in p),
    "double_url_encode": lambda p: "".join(
        f"%25{ord(c):02X}" if c in "' \"=" else c for c in p
    ),
    "case_toggle": lambda p: "".join(
        c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(p)
    ),
    "hex_encode_strings": lambda p: re.sub(
        r"'([^']*)'",
        lambda m: "0x" + m.group(1).encode().hex(),
        p,
    ),
}


def detect_waf(response_headers: dict, response_body: str = "", status_code: int = 200) -> str | None:
    headers_lower = {k.lower(): v.lower() for k, v in response_headers.items()}
    body_lower = response_body.lower()

    for waf_name, signatures in WAF_SIGNATURES.items():
        for sig in signatures:
            if sig.lower() in headers_lower or sig.lower() in body_lower:
                return waf_name

    if status_code in WAF_STATUS_CODES and ("blocked" in body_lower or "forbidden" in body_lower):
        return "Unknown WAF"

    return None


def apply_tamper(payload: str, tamper: str) -> str:
    func = TAMPER_FUNCTIONS.get(tamper)
    if func:
        return func(payload)
    return payload


def get_bypass_payloads(original_payload: str) -> list[str]:
    variants = [original_payload]
    for name, func in TAMPER_FUNCTIONS.items():
        try:
            variants.append(func(original_payload))
        except Exception:
            pass
    return list(dict.fromkeys(variants))
