"""
Skills library bridge.
Reads SKILL.md files from Anthropic-Cybersecurity-Skills and extracts
payload examples from workflow sections for use as attack payloads.
"""
from __future__ import annotations
import re
from pathlib import Path

SKILLS_BASE = Path(__file__).parent.parent.parent / "Anthropic-Cybersecurity-Skills" / "skills"

VECTOR_KEYWORDS = {
    "sqli": ["sql-injection", "sqlmap", "sql_injection", "second-order-sql"],
    "xss": ["xss-vulnerabilities", "cross-site-scripting", "xss-with-burpsuite"],
    "ssrf": ["ssrf", "blind-ssrf", "server-side-request"],
    "lfi": ["directory-traversal", "path-traversal", "local-file-inclusion"],
    "ssti": ["template-injection", "ssti"],
    "nosql": ["nosql-injection"],
    "idor": ["broken-object", "idor", "bola", "broken-function-level"],
    "csrf": ["csrf", "cross-site-request"],
    "xxe": ["xxe", "xml-external-entity", "xml-injection"],
    "deserialization": ["insecure-deserialization"],
    "api": ["api-security", "jwt-vulnerabilities", "oauth2"],
    "cmdi": ["command-injection", "os-command", "rce", "code-execution"],
    "jwt":  ["jwt-vulnerabilities", "jwt-auth", "token-forgery", "oauth2"],
}

PAYLOAD_PATTERN = re.compile(
    r"```(?:bash|python|http|sql|javascript)?\s*(.*?)```",
    re.DOTALL,
)


def extract_payloads_from_skill(vector: str, limit: int = 20) -> list[str]:
    if not SKILLS_BASE.exists():
        return []

    keywords = VECTOR_KEYWORDS.get(vector, [vector])
    payloads = []

    for skill_dir in sorted(SKILLS_BASE.iterdir()):
        if not skill_dir.is_dir():
            continue
        dir_lower = skill_dir.name.lower()
        if not any(kw in dir_lower for kw in keywords):
            continue

        skill_file = skill_dir / "SKILL.md"
        if not skill_file.exists():
            continue

        content = skill_file.read_text(encoding="utf-8", errors="ignore")

        for block in PAYLOAD_PATTERN.findall(content):
            for line in block.splitlines():
                line = line.strip()
                if (
                    line
                    and len(line) > 4
                    and not line.startswith("#")
                    and not line.startswith("//")
                    and not line.startswith("$")
                    and not line.startswith("python")
                    and not line.startswith("sqlmap")
                ):
                    payloads.append(line)

        if len(payloads) >= limit:
            break

    return list(dict.fromkeys(payloads))[:limit]


def load_payloads_file(vector: str) -> list[str]:
    payload_file = Path(__file__).parent.parent / "payloads" / f"{vector}.txt"
    if not payload_file.exists():
        return []
    return [
        line.strip()
        for line in payload_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]


def get_payloads(vector: str) -> list[str]:
    from_skills = extract_payloads_from_skill(vector)
    from_file = load_payloads_file(vector)
    combined = from_skills + from_file
    return list(dict.fromkeys(combined))[:50]
