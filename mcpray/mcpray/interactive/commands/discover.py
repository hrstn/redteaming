"""MCP server discovery REPL command handler: discover."""
from __future__ import annotations

from typing import TYPE_CHECKING

from rich.console import Console

if TYPE_CHECKING:
    from ..state import REPLState


# ─── discover ─────────────────────────────────────────────────────────────────

async def cmd_discover(state: "REPLState", args: list[str], console: Console) -> None:
    """Discover MCP servers on a host or CIDR range.

    Usage:
      discover <target>
      discover <target> --ports 8000-9000
      discover <target> --ports 3000,8000,8080
      discover <target> --no-enum
      discover <target> --https-only
    """
    from ...scanners.discovery import (
        discover as _discover, _parse_port_range, _DEFAULT_PORTS, _MCP_PATHS
    )
    from rich.table import Table
    from rich import box as _box
    import dataclasses, json

    if not args or args[0].startswith("-"):
        console.print("[yellow]Usage: discover <target> [--ports X] [--no-enum][/]")
        return

    target = args[0]
    ports_str = None
    no_enum = "--no-enum" in args
    https_only = "--https-only" in args
    http_only = "--http-only" in args

    for i, a in enumerate(args):
        if a == "--ports" and i + 1 < len(args):
            ports_str = args[i + 1]

    ports = _parse_port_range(ports_str) if ports_str else _DEFAULT_PORTS
    schemes = ["https"] if https_only else (["http"] if http_only else ["http", "https"])

    console.print(f"[dim]Discovering MCP servers on {target} "
                  f"({len(ports)} ports, {len(schemes)} scheme(s))...[/]")

    with console.status(f"[cyan]Scanning {target}...[/]"):
        result = await _discover(
            target=target,
            ports=ports,
            paths=_MCP_PATHS,
            timeout=5,
            port_concurrency=150,
            enum_capabilities=not no_enum,
            schemes=schemes,
        )

    servers = result.reachable_servers
    console.print(
        f"[dim]{result.hosts_scanned} host(s) · {result.ports_probed} port probes · "
        f"{result.endpoints_tried} endpoint checks · {result.scan_duration_s}s[/]"
    )

    if not servers:
        console.print("[yellow]No MCP servers found.[/]")
        return

    console.print(f"[bold green]{len(servers)} server(s) discovered:[/]")

    tbl = Table(box=_box.SIMPLE, padding=(0, 1))
    tbl.add_column("URL", style="bold cyan")
    tbl.add_column("Auth", width=5)
    tbl.add_column("Framework", width=12)
    tbl.add_column("Caps", width=18)
    tbl.add_column("Flags")

    for srv in servers:
        auth_str = "[red]NO[/]" if not srv.auth_required else "[green]YES[/]"
        flags = " ".join(f"[bold red]{f}[/]" if f == "ANON" else f"[yellow]{f}[/]"
                         for f in srv.risk_flags)
        tbl.add_row(srv.url, auth_str, srv.framework or "—",
                    srv.capability_summary, flags)

    console.print(tbl)

    # Auto-suggest scan
    if servers:
        console.print(
            f"\n[dim]Scan with:[/] mcpray scan --active {servers[0].url}"
        )


# ─── Command registry ─────────────────────────────────────────────────────────

COMMANDS: dict[str, tuple] = {
    "discover": (cmd_discover, "Discover MCP servers on host/CIDR"),
}
