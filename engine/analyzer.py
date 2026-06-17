"""
Claude API-powered attack triage.
Sends structured recon JSON + skill summaries → gets ranked attack plan.
Context budget: ~3000-4000 tokens max (no raw DOM, no full SKILL.md).
"""
from __future__ import annotations
import json
import os
import re
from pathlib import Path

from anthropic import AsyncAnthropic
from rich.console import Console

console = Console()

SKILLS_BASE = Path(__file__).parent.parent.parent / "Anthropic-Cybersecurity-Skills" / "skills"

WEB_SKILL_KEYWORDS = {
    "sqli": ["sql-injection", "sqlmap", "sql_injection"],
    "xss": ["xss", "cross-site-scripting"],
    "ssrf": ["ssrf", "server-side-request"],
    "lfi": ["directory-traversal", "local-file-inclusion", "path-traversal"],
    "ssti": ["template-injection", "ssti"],
    "nosql": ["nosql-injection"],
    "idor": ["broken-object", "idor", "bola"],
    "csrf": ["csrf", "cross-site-request-forgery"],
    "xxe": ["xxe", "xml-external-entity"],
    "deserialization": ["insecure-deserialization", "deserialization"],
    "api": ["api-security", "jwt", "oauth"],
}


def _load_skill_summary(skill_dir: Path) -> str | None:
    skill_file = skill_dir / "SKILL.md"
    if not skill_file.exists():
        return None
    content = skill_file.read_text(encoding="utf-8", errors="ignore")

    desc_match = re.search(r"description:\s*(.+)", content)
    when_match = re.search(r"## When to Use\n((?:- .+\n?){1,3})", content)

    desc = desc_match.group(1).strip() if desc_match else ""
    when = when_match.group(1).strip() if when_match else ""
    name = skill_dir.name

    return f"**{name}**: {desc}\n{when}"


def _gather_skill_context(attack_vectors: list[str]) -> str:
    summaries = []
    if not SKILLS_BASE.exists():
        return ""

    for vector in attack_vectors:
        keywords = WEB_SKILL_KEYWORDS.get(vector, [vector])
        for skill_dir in SKILLS_BASE.iterdir():
            if not skill_dir.is_dir():
                continue
            dir_name = skill_dir.name.lower()
            if any(kw in dir_name for kw in keywords):
                summary = _load_skill_summary(skill_dir)
                if summary:
                    summaries.append(summary)
                    break

    return "\n\n".join(summaries[:6])


def _build_prompt(recon: dict, passive_hits: list[dict], skill_context: str) -> str:
    recon_json = json.dumps({
        "tech_stack": recon.get("tech_stack", []),
        "attack_points": recon.get("attack_points", [])[:30],
        "ghost_apis": recon.get("ghost_apis", [])[:15],
        "interesting_headers": recon.get("interesting_headers", {}),
        "notes": recon.get("notes", []),
        "passive_hits": [
            {"path": h["path"], "status": h["status"]}
            for h in passive_hits[:10]
        ],
    }, indent=2)

    prompt = f"""Sen bir web CTF uzmanısın. Aşağıdaki recon sonuçlarını analiz et ve saldırı planı oluştur.

## Recon Sonuçları
```json
{recon_json}
```

## İlgili Skills (kısa özetler)
{skill_context if skill_context else "N/A"}

## Görev
1. Tech stack ve attack point'lere bakarak hangi saldırı vektörlerinin işe yarayacağını belirle.
2. Her vektör için confidence score (0.0-1.0) ver.
3. Her vektör için o siteye ÖZGÜ payload örnekleri üret (generic değil, stack'e göre).
4. CTF'te flag nerede olabilir? Dinamik flag ihtimalini de değerlendir.

## Çıktı Formatı (sadece JSON, başka bir şey yazma)
```json
{{
  "attack_plan": [
    {{
      "vector": "sqli",
      "confidence": 0.85,
      "target": "/api/users?id=1",
      "payloads": ["1' OR 1=1--", "1 UNION SELECT null,table_name FROM information_schema.tables--"],
      "reasoning": "PostgreSQL hint: error mesajında 'pg_' prefix gördüm",
      "flag_hint": "users tablosundaki password kolonu flag olabilir"
    }}
  ],
  "quick_wins": ["robots.txt'te /admin-secret bulundu", ".git exposure var"],
  "flag_philosophy": "Admin şifre flag'i olabilir, SQLi ile users tablosunu dök"
}}
```
"""
    return prompt


async def run_triage(
    recon: dict,
    passive_hits: list[dict],
    api_key: str | None = None,
) -> dict:
    key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        console.print("[yellow][!] ANTHROPIC_API_KEY bulunamadı, AI triage atlanıyor.[/]")
        return {
            "attack_plan": [
                {"vector": v, "confidence": 0.5, "target": "?", "payloads": [], "reasoning": "AI triage yok"}
                for v in ["sqli", "xss", "lfi", "ssti", "ssrf", "idor", "nosql"]
            ],
            "quick_wins": [],
            "flag_philosophy": "Tüm vektörleri sırayla dene.",
        }

    tech = recon.get("tech_stack", [])
    attack_vectors = list(WEB_SKILL_KEYWORDS.keys())
    skill_context = _gather_skill_context(attack_vectors)

    prompt = _build_prompt(recon, passive_hits, skill_context)

    client = AsyncAnthropic(api_key=key)
    console.print("  [dim]Claude API'ye istek gönderiliyor...[/dim]")

    try:
        message = await client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = message.content[0].text.strip()
    except Exception as e:
        console.print(f"[red][!] Claude API hatası: {e}[/]")
        return {"attack_plan": [], "quick_wins": [], "flag_philosophy": "API hatası"}

    json_match = re.search(r"```json\s*([\s\S]+?)\s*```", raw)
    if json_match:
        raw = json_match.group(1)

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        console.print("[yellow][!] Claude yanıtı parse edilemedi, ham metin döndürülüyor.[/]")
        return {"attack_plan": [], "quick_wins": [], "flag_philosophy": raw[:500]}
