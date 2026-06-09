"""Shared helpers and constants for REPL command handlers.

These are imported by multiple command submodules.
"""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from rich.console import Console

from ...ai.payloads import PayloadEngine

if TYPE_CHECKING:
    from ..state import REPLState

_SEV_STYLE = {
    "CRITICAL": "bold red",
    "HIGH": "bold dark_orange",
    "MEDIUM": "bold yellow",
    "LOW": "bold green",
    "INFORMATIONAL": "dim",
}
_engine = PayloadEngine()


async def _ainput(prompt: str) -> str:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, input, prompt)


def _print_ai_analysis(result: dict, console: Console) -> None:
    ver = result.get("verification", "N/A")
    conf = result.get("confidence", 0.0)
    adj = result.get("risk_adjustment", "same")
    provider = result.get("_provider", "?")
    model = result.get("_model", "?")

    ver_style = {
        "confirmed": "bold red",
        "likely": "bold dark_orange",
        "possible": "bold yellow",
        "false_positive": "bold green",
    }.get(ver, "bold")

    bar = "█" * int(conf * 20) + "░" * (20 - int(conf * 20))
    conf_color = "red" if conf >= 0.8 else "yellow" if conf >= 0.5 else "green"

    console.print(f"  Verification: [{ver_style}]{ver.upper()}[/]  "
                  f"Confidence: [{conf_color}]{conf:.2f}[/] {bar}  "
                  f"[dim]via {model}@{provider}[/]")
    console.print(f"  Risk Adjustment: [bold]{adj.upper()}[/]")

    reasoning = result.get("reasoning", "")
    if reasoning:
        console.print(f"\n  [bold]Reasoning:[/] {reasoning[:400]}")

    indicators = result.get("key_indicators", [])
    if indicators:
        console.print("\n  [bold]Key Indicators:[/]")
        for ind in indicators[:5]:
            console.print(f"    [dim]▸[/] {ind}")

    if "_hybrid_disagreement" in result:
        console.print(f"\n  [yellow]⚠ Disagreement:[/] {result['_hybrid_disagreement']}")

    if "_hybrid_note" in result:
        console.print(f"\n  [dim]Note:[/] {result['_hybrid_note']}")
