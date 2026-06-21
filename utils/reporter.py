"""
Terminal output and write-up export.
"""
from __future__ import annotations
import json
import re
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console(legacy_windows=False)


def print_banner():
    console.print(Panel.fit(
        "[bold red]T-Web[/bold red] [dim]CTF Web Attack Tool[/dim]\n"
        "[dim]by Tajaa[/dim]",
        border_style="red",
    ))


def print_phase(phase: int, name: str):
    icons = {0: ">>", 1: "~>", 2: "!!", 3: "**"}
    icon = icons.get(phase, ">")
    console.print(f"\n[bold cyan]{icon}  Phase {phase}: {name}[/bold cyan]")


def print_findings(findings: list[dict]):
    if not findings:
        console.print("[dim]  Bulgu yok.[/dim]")
        return

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold magenta")
    table.add_column("Tip", style="cyan", min_width=16)
    table.add_column("Değer", style="white", min_width=30)
    table.add_column("Güvenilirlik", style="green", min_width=14)

    for f in findings:
        confidence = f.get("confidence", 0.0)
        bar_len = int(confidence * 8)
        bar = "█" * bar_len + "░" * (8 - bar_len)
        pct = f"{int(confidence * 100)}%"
        style = "bold yellow" if confidence >= 0.7 else "white"

        table.add_row(
            f["type"],
            f"[{style}]{f['value'][:80]}[/{style}]",
            f"{bar} {pct}",
        )

    console.print(table)


def print_flag_found(flag: str, vector: str, url: str):
    console.print(Panel(
        f"[bold green]**  FLAG BULUNDU![/bold green]\n\n"
        f"[bold white]{flag}[/bold white]\n\n"
        f"[dim]Vektör: {vector} | URL: {url}[/dim]",
        border_style="green",
        expand=False,
    ))


def export_finding(
    flag: str,
    payload: str,
    vector: str,
    request_url: str,
    request_method: str,
    request_headers: dict,
    response_status: int,
    response_headers: dict,
    response_body_preview: str,
) -> str:
    target_host = re.sub(r"[^\w.-]", "_", request_url.split("/")[2])
    filename = f"tweb_report_{target_host}.json"

    report = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "flag": flag,
        "vector": vector,
        "request": {
            "url": request_url,
            "method": request_method,
            "payload": payload,
            "headers": request_headers,
        },
        "response": {
            "status": response_status,
            "headers": response_headers,
            "body_preview": response_body_preview[:500],
        },
    }

    Path(filename).write_text(json.dumps(report, indent=2, ensure_ascii=False))
    console.print(f"[dim]  Write-up kaydedildi: {filename}[/dim]")
    return filename
