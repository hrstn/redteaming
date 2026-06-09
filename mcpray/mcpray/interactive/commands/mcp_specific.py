"""MCP-specific check REPL command handlers: pi, shadow, poison."""
from __future__ import annotations

from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel

if TYPE_CHECKING:
    from ..state import REPLState


# ─── pi (indirect prompt injection) ───────────────────────────────────────────

async def cmd_pi(state: "REPLState", args: list[str], console: Console) -> None:
    """Indirect prompt injection scanner — checks resources/tools for PI payloads.

    Usage:
      pi
    """
    from ...scanners.indirect_pi import IndirectPIScanner
    from ...client import MCPClient
    from rich.table import Table as _Table
    from rich import box as _box

    if not state.require_scan():
        console.print("[yellow]Run: scan[/]")
        return

    async with MCPClient(state.target, headers=state.mcp_client.headers,
                         timeout=state.mcp_client.timeout) as client:
        scanner = IndirectPIScanner(client)
        with console.status("[cyan]Scanning for indirect prompt injection...[/]"):
            result = await scanner.run(state.scan_result.server_inventory)

    console.print(Panel(
        f"Resources checked: {result.total_resources_checked}\n"
        f"Tools checked: {result.total_tools_checked}\n"
        f"[bold red]Triggered PI payloads: {result.triggered_count}[/]\n"
        f"Total findings: {len(result.findings)}",
        title="[bold red]Indirect PI Scan[/]", border_style="red",
    ))

    if result.findings:
        tbl = _Table(box=_box.SIMPLE, padding=(0, 1))
        tbl.add_column("Type", width=12)
        tbl.add_column("Source", width=30)
        tbl.add_column("Severity", width=10)
        tbl.add_column("Triggered", width=10)
        tbl.add_column("Patterns")
        for f in result.findings:
            tbl.add_row(
                f.source_type, f.source_name[:28],
                f.severity, "YES" if f.triggered else "no",
                ", ".join(f.suspicious_content[:2])[:40],
            )
        console.print(tbl)
    else:
        console.print("[green]✓ No prompt injection patterns detected.[/]")


# ─── shadow (tool shadowing) ──────────────────────────────────────────────────

async def cmd_shadow(state: "REPLState", args: list[str], console: Console) -> None:
    """Tool shadow detector — finds duplicate names, description impersonation, dangerous descriptions.

    Usage:
      shadow
    """
    from ...scanners.tool_shadow import ToolShadowScanner

    if not state.require_scan():
        console.print("[yellow]Run: scan[/]")
        return

    scanner = ToolShadowScanner()
    result = scanner.run(state.scan_result.server_inventory)

    if not result.findings:
        console.print("[green]✓ No tool shadowing issues detected.[/]")
        return

    console.print(Panel(
        f"[bold red]{len(result.findings)} issue(s) found[/]",
        title="[bold red]Tool Shadow Analysis[/]", border_style="red",
    ))
    for f in result.findings:
        sev_map = {"CRITICAL": "bold red", "HIGH": "bold dark_orange", "MEDIUM": "bold yellow"}
        style = sev_map.get(f.severity, "bold")
        console.print(
            f"  [{style}][{f.severity}][/] [bold]{f.finding_type}[/] "
            f"— {', '.join(f.tool_names[:3])}  [dim]{f.detail[:60]}[/]"
        )


# ─── poison (context poisoning) ───────────────────────────────────────────────

async def cmd_poison(state: "REPLState", args: list[str], console: Console) -> None:
    """Context window poisoning scanner — detects oversized resources, hidden text, fake system messages.

    Usage:
      poison
    """
    from ...scanners.context_poison import ContextPoisonScanner
    from ...client import MCPClient

    if not state.require_scan():
        console.print("[yellow]Run: scan[/]")
        return

    async with MCPClient(state.target, headers=state.mcp_client.headers,
                         timeout=state.mcp_client.timeout) as client:
        scanner = ContextPoisonScanner(client)
        with console.status("[cyan]Scanning for context poisoning...[/]"):
            result = await scanner.run(state.scan_result.server_inventory)

    console.print(
        f"[dim]Resources checked: {result.resources_checked}  "
        f"Bytes read: {result.total_bytes_read:,}[/]"
    )

    if not result.findings:
        console.print("[green]✓ No context poisoning detected.[/]")
        return

    console.print(f"[bold red]{len(result.findings)} poisoning pattern(s) found:[/]")
    for f in result.findings:
        sev_map = {"CRITICAL": "bold red", "HIGH": "bold dark_orange", "MEDIUM": "bold yellow"}
        style = sev_map.get(f.severity, "bold")
        size_info = f" ({f.byte_size:,}B)" if f.byte_size else ""
        console.print(
            f"  [{style}][{f.severity}][/] [bold]{f.poison_type}[/]{size_info}"
            f"  [bold]{f.resource_name}[/]  [dim]{f.detail[:60]}[/]"
        )


# ─── Command registry ─────────────────────────────────────────────────────────

COMMANDS: dict[str, tuple] = {
    "pi":     (cmd_pi,     "Indirect prompt injection scanner"),
    "shadow": (cmd_shadow, "Tool shadowing / impersonation detector"),
    "poison": (cmd_poison, "Context window poisoning scanner"),
}
