from __future__ import annotations

import asyncio
import json
import logging
import sys
from collections import Counter
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import box
from rich.text import Text

from .findings import Severity, ScanResult
from .scanner import run_scan
from .reporters import json_reporter, sarif_reporter, html_reporter

console = Console(stderr=False)

_SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH": "bold dark_orange",
    "MEDIUM": "bold yellow",
    "LOW": "bold green",
    "INFORMATIONAL": "dim",
}

_SEV_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
              Severity.LOW: 3, Severity.INFORMATIONAL: 4}


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s — %(message)s",
        datefmt="%H:%M:%S",
    )


def _print_banner() -> None:
    from . import __version__

    banner = (
        "[bold cyan] ███╗   ███╗ ██████╗██████╗ ██████╗  █████╗ ██╗   ██╗[/]\n"
        "[bold cyan] ████╗ ████║██╔════╝██╔══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝[/]\n"
        "[bold cyan] ██╔████╔██║██║     ██████╔╝██████╔╝███████║ ╚████╔╝ [/]\n"
        "[bold cyan] ██║╚██╔╝██║██║     ██╔═══╝ ██╔══██╗██╔══██║  ╚██╔╝  [/]\n"
        "[bold cyan] ██║ ╚═╝ ██║╚██████╗██║     ██║  ██║██║  ██║   ██║   [/]\n"
        "[bold cyan] ╚═╝     ╚═╝ ╚═════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   [/]\n"
        "\n"
        f"           [bold white]mcpray v{__version__} — MCP Security Scanner[/]\n"
        "           [dim]Licensed under the MIT License[/]\n"
        "           [dim italic]For authorized security testing only.[/]\n"
        "           [dim italic]Using this tool against systems without explicit "
        "written permission is illegal.[/]"
    )
    console.print(Panel(banner, border_style="cyan", padding=(0, 2)))
    console.print()


from . import __version__


@click.group()
@click.version_option(__version__, "--version", prog_name="mcpray")
@click.pass_context
def main(ctx: click.Context) -> None:
    """mcpray — MCP Server Security Scanner"""
    if ctx.invoked_subcommand is not None:
        _print_banner()


@main.command()
@click.argument("target")
@click.option("--active", is_flag=True, default=False,
              help="Enable active (non-destructive) testing. Sends probe payloads to the server.")
@click.option("--deep", is_flag=True, default=False,
              help="Deep scan: read resource contents and run extended checks.")
@click.option("--output", "-o", default=None,
              help="Base path for output files (e.g. results → results.json, results.html, results.sarif)")
@click.option("--format", "-f", "fmt", default="all",
              type=click.Choice(["json", "sarif", "html", "all"], case_sensitive=False),
              help="Output format(s). Default: all.")
@click.option("--header", "-H", multiple=True,
              help="Custom HTTP header (Name: Value). Can be repeated.")
@click.option("--rules", default=None,
              help="Path to custom rules JSON file.")
@click.option("--timeout", default=30, show_default=True,
              help="HTTP request timeout in seconds.")
@click.option("--verbose", "-v", is_flag=True, default=False,
              help="Enable verbose logging.")
@click.option("--no-color", is_flag=True, default=False,
              help="Disable colored output.")
def scan(
    target: str,
    active: bool,
    deep: bool,
    output: str | None,
    fmt: str,
    header: tuple[str, ...],
    rules: str | None,
    timeout: int,
    verbose: bool,
    no_color: bool,
) -> None:
    """Scan an MCP server for security vulnerabilities.

    TARGET can be an HTTP(S) URL or a stdio command.

    \b
    Examples:
      mcpray scan http://localhost:8000/mcp
      mcpray scan https://mcp.example.com/mcp --output results
      mcpray scan --active --deep http://localhost:8000/mcp
      mcpray scan --header "Authorization: Bearer TOKEN" http://example.com/mcp
    """
    _configure_logging(verbose)
    global console
    if no_color:
        console = Console(no_color=True)

    # Parse headers
    custom_headers: dict[str, str] = {}
    for h in header:
        if ":" in h:
            k, _, v = h.partition(":")
            custom_headers[k.strip()] = v.strip()

    if active:
        console.print(
            Panel(
                "[bold yellow]Active testing enabled.[/] Non-destructive probes will be sent to the target.\n"
                "Only use against systems you are authorized to test.",
                title="[bold]WARNING",
                border_style="yellow",
            )
        )

    _print_header(target, active)

    result = asyncio.run(_run_with_progress(
        target, active, custom_headers, timeout, rules
    ))

    _print_results(result)

    # Write output files
    if output:
        base = Path(output).stem if "." in Path(output).name else output
        paths_written = []

        if fmt in ("json", "all"):
            p = f"{base}.json"
            json_reporter.write(result, p)
            paths_written.append(p)

        if fmt in ("sarif", "all"):
            p = f"{base}.sarif"
            sarif_reporter.write(result, p)
            paths_written.append(p)

        if fmt in ("html", "all"):
            p = f"{base}.html"
            html_reporter.write(result, p)
            paths_written.append(p)

        console.print()
        console.print(f"[bold]Reports written:[/] {', '.join(paths_written)}")
    else:
        # Auto-output
        stem = _safe_stem(target)
        json_reporter.write(result, f"{stem}.json")
        html_reporter.write(result, f"{stem}.html")
        sarif_reporter.write(result, f"{stem}.sarif")
        console.print()
        console.print(
            f"[dim]Reports:[/] {stem}.json, {stem}.html, {stem}.sarif"
        )

    # Exit with non-zero on critical/high
    if result.risk_level in (Severity.CRITICAL, Severity.HIGH):
        sys.exit(1)


@main.command()
@click.argument("target")
@click.option("--ai-mode", default=None,
              type=click.Choice(["openai", "ollama", "hybrid"], case_sensitive=False),
              help="Enable AI analysis (openai|ollama|hybrid).")
@click.option("--ai-key", default=None, envvar="OPENAI_API_KEY",
              help="OpenAI-compatible API key (or set OPENAI_API_KEY env var).")
@click.option("--ai-url", default="https://api.openai.com/v1",
              help="OpenAI-compatible base URL (for LM Studio / vLLM use their endpoint).")
@click.option("--ai-model", default="gpt-4o-mini", show_default=True,
              help="OpenAI model name.")
@click.option("--ollama-url", default="http://localhost:11434", show_default=True,
              help="Ollama server base URL.")
@click.option("--ollama-model", default="llama3.2", show_default=True,
              help="Ollama model name.")
@click.option("--load", default=None,
              help="Load an existing scan result JSON instead of scanning immediately.")
@click.option("--unsafe-mode", is_flag=True, default=False,
              help="Allow actual tool execution from the REPL (default: dry-run only).")
@click.option("--header", "-H", multiple=True,
              help="Custom HTTP header (Name: Value). Can be repeated.")
@click.option("--timeout", default=30, show_default=True)
@click.option("--log-dir", default=".", show_default=True,
              help="Directory for session audit log.")
def interactive(
    target: str,
    ai_mode: str | None,
    ai_key: str | None,
    ai_url: str,
    ai_model: str,
    ollama_url: str,
    ollama_model: str,
    load: str | None,
    unsafe_mode: bool,
    header: tuple[str, ...],
    timeout: int,
    log_dir: str,
) -> None:
    """Interactive REPL for MCP security analysis.

    \b
    Examples:
      mcpray interactive http://localhost:8000/mcp
      mcpray interactive --ai-mode openai http://target/mcp
      mcpray interactive --ai-mode hybrid --ollama-model llama3.2 http://target/mcp
      mcpray interactive --load results.json http://target/mcp
      mcpray interactive --unsafe-mode http://localhost:8000/mcp
    """
    from .interactive.repl import run_interactive

    custom_headers: dict[str, str] = {}
    for h in header:
        if ":" in h:
            k, _, v = h.partition(":")
            custom_headers[k.strip()] = v.strip()

    if unsafe_mode:
        console.print(
            Panel(
                "[bold red]UNSAFE MODE enabled.[/] Tool calls may be executed against the target.\n"
                "Only use against systems you are explicitly authorised to test.",
                title="WARNING",
                border_style="red",
            )
        )

    asyncio.run(run_interactive(
        target=target,
        ai_mode=ai_mode,
        openai_api_key=ai_key,
        openai_base_url=ai_url,
        openai_model=ai_model,
        ollama_base_url=ollama_url,
        ollama_model=ollama_model,
        load_file=load,
        unsafe_mode=unsafe_mode,
        headers=custom_headers,
        timeout=timeout,
        log_dir=log_dir,
    ))


@main.command()
@click.argument("json_file")
@click.option("--format", "-f", "fmt", default="html",
              type=click.Choice(["json", "sarif", "html"], case_sensitive=False))
@click.option("--output", "-o", default=None)
def report(json_file: str, fmt: str, output: str | None) -> None:
    """Re-generate a report from a saved JSON scan result.

    \b
    Examples:
      mcpray report results.json
      mcpray report results.json --format sarif --output ci_results.sarif
    """
    data = json.loads(Path(json_file).read_text())
    # Reconstruct a minimal ScanResult-compatible dict for re-reporting
    console.print(f"[dim]Loaded: {json_file}[/]")

    out = output or Path(json_file).stem + f".{fmt}"
    if fmt == "html":
        # We need a full ScanResult object — rebuild from dict
        result = _reconstruct_result(data)
        html_reporter.write(result, out)
    elif fmt == "sarif":
        result = _reconstruct_result(data)
        sarif_reporter.write(result, out)
    else:
        # JSON is the source — just pretty-print it
        Path(out).write_text(json.dumps(data, indent=2))

    console.print(f"[green]✓[/] Report written: {out}")


@main.command()
@click.argument("targets", nargs=-1)
@click.option("--active", is_flag=True, default=False)
@click.option("--output-dir", "-d", default=".", show_default=True)
@click.option("--timeout", default=30, show_default=True)
def batch(targets: tuple[str, ...], active: bool, output_dir: str, timeout: int) -> None:
    """Batch-scan multiple MCP servers.

    \b
    Examples:
      mcpray batch http://server1/mcp http://server2/mcp --output-dir ./reports
    """
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    for target in targets:
        console.rule(f"[bold]{target}")
        try:
            result = asyncio.run(run_scan(target, active=active, timeout=timeout))
            stem = out_dir / _safe_stem(target)
            json_reporter.write(result, f"{stem}.json")
            html_reporter.write(result, f"{stem}.html")
            sarif_reporter.write(result, f"{stem}.sarif")
            _print_summary_line(result)
        except Exception as e:
            console.print(f"[red]ERROR:[/] {target} — {e}")


# ─── discover ─────────────────────────────────────────────────────────────────

@main.command()
@click.argument("target")
@click.option("--ports", "-p", default=None,
              help="Ports to probe. Comma-separated or range (e.g. 8000-9000,3000). "
                   "Default: common MCP ports.")
@click.option("--paths", default=None,
              help="URL paths to try. Comma-separated. Default: /mcp,/sse,/api/mcp,…")
@click.option("--timeout", default=5, show_default=True,
              help="Per-request timeout in seconds.")
@click.option("--concurrency", default=200, show_default=True,
              help="Max parallel TCP probes.")
@click.option("--no-enum", is_flag=True, default=False,
              help="Skip capability enumeration (faster, less noisy).")
@click.option("--https-only", is_flag=True, default=False,
              help="Probe HTTPS only.")
@click.option("--http-only", is_flag=True, default=False,
              help="Probe HTTP only.")
@click.option("--output", "-o", default=None,
              help="Write JSON results to this file.")
@click.option("--verbose", "-v", is_flag=True, default=False)
def discover(
    target: str,
    ports: str | None,
    paths: str | None,
    timeout: int,
    concurrency: int,
    no_enum: bool,
    https_only: bool,
    http_only: bool,
    output: str | None,
    verbose: bool,
) -> None:
    """Discover MCP servers on a host, IP range, or CIDR block.

    Performs TCP port scanning, HTTP endpoint probing, framework fingerprinting,
    and optional capability enumeration. Supports CIDR notation for network sweeps.

    \b
    Examples:
      mcpray discover 192.168.1.100
      mcpray discover 192.168.1.0/24 --ports 8000-9000
      mcpray discover http://target.com --no-enum
      mcpray discover 10.0.0.0/24 --ports 3000,8000,8080 --http-only
      mcpray discover 10.10.10.0/24 --output discovered.json
    """
    _configure_logging(verbose)
    asyncio.run(_run_discover(
        target=target,
        ports_str=ports,
        paths_str=paths,
        timeout=timeout,
        concurrency=concurrency,
        enum_caps=not no_enum,
        schemes=["https"] if https_only else (["http"] if http_only else ["http", "https"]),
        output=output,
    ))


async def _run_discover(
    target: str,
    ports_str: str | None,
    paths_str: str | None,
    timeout: int,
    concurrency: int,
    enum_caps: bool,
    schemes: list[str],
    output: str | None,
) -> None:
    from .scanners.discovery import (
        discover as _discover, _parse_port_range, _DEFAULT_PORTS, _MCP_PATHS
    )

    ports = _parse_port_range(ports_str) if ports_str else _DEFAULT_PORTS
    paths = [p.strip() for p in paths_str.split(",")] if paths_str else _MCP_PATHS

    console.print(
        Panel(
            f"[bold]Target:[/]     {target}\n"
            f"[bold]Ports:[/]      {len(ports)} ports\n"
            f"[bold]Paths:[/]      {len(paths)} paths\n"
            f"[bold]Schemes:[/]    {', '.join(schemes)}\n"
            f"[bold]Enum caps:[/]  {'Yes' if enum_caps else 'No (--no-enum)'}",
            title="[bold green]mcpray — Discovery[/]",
            border_style="green",
            padding=(0, 2),
        )
    )
    console.print()

    progress_q: asyncio.Queue = asyncio.Queue()

    async def _show_progress() -> None:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      console=console, transient=True) as prog:
            task = prog.add_task("Scanning...", total=None)
            while True:
                try:
                    msg = await asyncio.wait_for(progress_q.get(), timeout=0.2)
                    kind, val = msg
                    if kind == "port_scan":
                        prog.update(task, description=f"Port scanning {val}...")
                    elif kind == "found":
                        prog.update(task, description=f"[green]Found:[/] {val}")
                    elif kind == "done":
                        break
                except asyncio.TimeoutError:
                    pass

    prog_task = asyncio.create_task(_show_progress())
    result = await _discover(
        target=target,
        ports=ports,
        paths=paths,
        timeout=timeout,
        port_concurrency=concurrency,
        enum_capabilities=enum_caps,
        schemes=schemes,
        on_progress=progress_q,
    )
    await progress_q.put(("done", ""))
    await prog_task

    _print_discovery_results(result)

    if output:
        import dataclasses
        data = {
            "target": result.target,
            "hosts_scanned": result.hosts_scanned,
            "ports_probed": result.ports_probed,
            "endpoints_tried": result.endpoints_tried,
            "scan_duration_s": result.scan_duration_s,
            "servers": [dataclasses.asdict(s) for s in result.reachable_servers],
        }
        Path(output).write_text(json.dumps(data, indent=2))
        console.print(f"[green]✓[/] Results written: {output}")


def _print_discovery_results(result) -> None:
    from .scanners.discovery import DiscoveryResult

    servers = result.reachable_servers
    duration = result.scan_duration_s

    # Summary line
    console.print(
        f"[dim]Scanned {result.hosts_scanned} host(s) · "
        f"{result.ports_probed} port probes · "
        f"{result.endpoints_tried} endpoint checks · "
        f"{duration}s[/]"
    )
    console.print()

    if not servers:
        console.print(Panel("[yellow]No MCP servers found.[/]", border_style="yellow"))
        return

    console.print(
        Panel(
            f"[bold green]{len(servers)} MCP server(s) discovered[/]",
            border_style="green",
        )
    )
    console.print()

    tbl = Table(box=box.ROUNDED, show_lines=False, padding=(0, 1))
    tbl.add_column("URL", style="bold cyan", no_wrap=True)
    tbl.add_column("Scheme", width=6)
    tbl.add_column("Auth", width=6)
    tbl.add_column("Framework", width=14)
    tbl.add_column("Server", width=16)
    tbl.add_column("Caps", width=20)
    tbl.add_column("Flags", width=12)
    tbl.add_column("ms", justify="right", width=6, style="dim")

    for srv in servers:
        auth_str = "[red]NO[/]" if not srv.auth_required else "[green]YES[/]"
        flags = " ".join(f"[bold red]{f}[/]" if f == "ANON" else f"[yellow]{f}[/]"
                         for f in srv.risk_flags)
        tbl.add_row(
            srv.url,
            srv.scheme.upper(),
            auth_str,
            srv.framework or "[dim]unknown[/]",
            (srv.server_name or "[dim]—[/]")[:16],
            srv.capability_summary,
            flags,
            str(int(srv.response_time_ms)),
        )

    console.print(tbl)
    console.print()

    # Detail panels for interesting servers
    for srv in servers:
        if not srv.auth_required or srv.tool_count > 0:
            notes = []
            if not srv.auth_required:
                notes.append("[bold red]Anonymous access — no authentication required[/]")
            if srv.tool_count:
                notes.append(f"[yellow]{srv.tool_count} tool(s) exposed[/]")
            if srv.resource_count or srv.template_count:
                notes.append(
                    f"[yellow]{srv.resource_count} resource(s), "
                    f"{srv.template_count} template(s)[/]"
                )
            if srv.server_version:
                notes.append(f"Version: {srv.server_version}")
            if notes:
                console.print(Panel(
                    "\n".join(notes),
                    title=f"[bold]{srv.url}[/]",
                    border_style="red" if not srv.auth_required else "yellow",
                    padding=(0, 2),
                ))

    # Scan hint
    if servers:
        first = servers[0]
        console.print(
            f"[dim]Scan discovered server:[/] "
            f"mcpray scan --active --deep {first.url}"
        )


# ─── sqli ─────────────────────────────────────────────────────────────────────

@main.command()
@click.argument("target")
@click.option("--template", "-t", default=None,
              help="URI template to inject into (e.g. price://{item}). Auto-detects if omitted.")
@click.option("--param", "-p", default=None,
              help="Template parameter name (e.g. item). Required when --template is given.")
@click.option("--dump-tables", is_flag=True, default=False,
              help="Enumerate database tables after confirming injection.")
@click.option("--dump-all", is_flag=True, default=False,
              help="Dump all tables and their data (implies --dump-tables).")
@click.option("--sqlmap-export", is_flag=True, default=False,
              help="Generate a local HTTP proxy script so sqlmap can target the injectable endpoint.")
@click.option("--proxy-port", default=18080, show_default=True,
              help="Port for the generated sqlmap proxy script.")
@click.option("--header", "-H", multiple=True,
              help="Custom HTTP header (Name: Value). Can be repeated.")
@click.option("--timeout", default=30, show_default=True)
@click.option("--verbose", "-v", is_flag=True, default=False)
def sqli(
    target: str,
    template: str | None,
    param: str | None,
    dump_tables: bool,
    dump_all: bool,
    sqlmap_export: bool,
    proxy_port: int,
    header: tuple[str, ...],
    timeout: int,
    verbose: bool,
) -> None:
    """SQL injection enumerator for injectable MCP resource templates.

    Confirms UNION/boolean/error-based SQLi, enumerates the database schema,
    and optionally dumps table contents. Works via MCP read_resource calls —
    no direct backend access needed.

    \b
    Examples:
      mcpray sqli http://localhost:8000/mcp
      mcpray sqli http://localhost:8000/mcp --template "price://{item}" --param item
      mcpray sqli http://localhost:8000/mcp --template "price://{item}" --param item --dump-tables
      mcpray sqli http://localhost:8000/mcp --template "price://{item}" --param item --dump-all
      mcpray sqli http://localhost:8000/mcp --template "price://{item}" --param item --sqlmap-export
    """
    _configure_logging(verbose)
    custom_headers: dict[str, str] = {}
    for h in header:
        if ":" in h:
            k, _, v = h.partition(":")
            custom_headers[k.strip()] = v.strip()

    asyncio.run(_run_sqli(
        target=target,
        template=template,
        param=param,
        dump_tables=dump_tables or dump_all,
        dump_all=dump_all,
        sqlmap_export=sqlmap_export,
        proxy_port=proxy_port,
        headers=custom_headers,
        timeout=timeout,
    ))


async def _run_sqli(
    target: str,
    template: str | None,
    param: str | None,
    dump_tables: bool,
    dump_all: bool,
    sqlmap_export: bool,
    proxy_port: int,
    headers: dict,
    timeout: int,
) -> None:
    from .client import MCPClient
    from .scanners.sqli import SqliEnumerator, generate_sqlmap_proxy

    console.print(
        Panel(
            f"[bold]Target:[/]  {target}\n"
            f"[bold]Template:[/] {template or '[dim]auto-detect[/]'}\n"
            f"[bold]Param:[/]    {param or '[dim]auto-detect[/]'}",
            title="[bold red]mcpray — SQLi Enumerator[/]",
            border_style="red",
            padding=(0, 2),
        )
    )
    console.print()

    async with MCPClient(target, headers=headers, timeout=timeout) as client:
        enum = SqliEnumerator(client)

        # Auto-detect injectable template if not specified
        if not template or not param:
            console.print("[dim]Auto-detecting injectable resource templates...[/]")
            inventory = await client.get_inventory()
            pairs = await enum.detect_injectable_templates(inventory.resource_templates)
            if not pairs:
                console.print("[yellow]No injectable resource templates found.[/]")
                return
            template, param = pairs[0]
            console.print(f"[green]✓[/] Injectable template: [bold]{template}[/] (param: [bold]{param}[/])")
            console.print()

        # Run enumeration
        with console.status(f"[cyan]Probing {template}...[/]"):
            result = await enum.run(
                template=template,
                param=param,
                dump_tables=dump_tables,
                dump_all=dump_all,
            )

        if not result.confirmed:
            console.print(Panel(
                f"[yellow]Not injectable.[/]\nTemplate: {template}\nParam: {param}",
                border_style="yellow",
            ))
            return

        # ── Confirmed ──
        console.print(Panel(
            f"[bold green]CONFIRMED[/]  {result.technique}\n"
            f"[bold]Template:[/] {result.template}\n"
            f"[bold]Param:[/]    {result.param}\n"
            f"[bold]Columns:[/]  {result.column_count}  (string col: {result.string_col})\n"
            f"[bold]Database:[/] {result.db_name or '[dim]unknown[/]'}",
            title="[bold red]SQL Injection Confirmed[/]",
            border_style="red",
        ))
        console.print()

        if result.error:
            console.print(f"[yellow]Note:[/] {result.error}")

        # Tables
        if result.tables:
            tbl = Table(title="Tables", box=box.SIMPLE, show_header=True)
            tbl.add_column("#", style="dim", width=4)
            tbl.add_column("Table Name", style="bold")
            for i, t in enumerate(result.tables, 1):
                tbl.add_row(str(i), t)
            console.print(tbl)
            console.print()

        # Dumped data
        for table, rows in result.data.items():
            if not rows:
                continue
            cols = result.columns.get(table, list(rows[0].keys()) if rows else [])
            dtbl = Table(title=f"[bold]{table}[/]", box=box.ROUNDED, show_lines=True)
            for col in cols:
                dtbl.add_column(col)
            for row in rows:
                dtbl.add_row(*[str(row.get(c, "")) for c in cols])
            console.print(dtbl)
            console.print()

        # sqlmap export
        if sqlmap_export:
            script, cmd = generate_sqlmap_proxy(template, param, target, proxy_port)
            proxy_file = "sqli_proxy.py"
            Path(proxy_file).write_text(script)
            console.print(Panel(
                f"[bold]Proxy script:[/] {proxy_file}\n"
                f"[bold]Start proxy:[/] python {proxy_file}\n\n"
                f"[bold]sqlmap command:[/]\n  [green]{cmd}[/]\n\n"
                f"[dim]The proxy translates sqlmap HTTP requests into MCP read_resource calls.[/]",
                title="[bold]sqlmap Export[/]",
                border_style="cyan",
            ))
            console.print(f"[green]✓[/] Proxy written: {proxy_file}")


# ─── cmdinj ───────────────────────────────────────────────────────────────────

@main.command()
@click.argument("target")
@click.option("--tool", "-t", required=True, help="Tool name containing the injectable parameter.")
@click.option("--param", "-p", required=True, help="Parameter name to inject into.")
@click.option("--base-value", default="test", show_default=True,
              help="Baseline safe value for the parameter.")
@click.option("--no-enum", is_flag=True, default=False,
              help="Skip system enumeration after confirming injection.")
@click.option("--lhost", default="", help="Listener host for reverse shell payloads.")
@click.option("--lport", default=4444, show_default=True, help="Listener port.")
@click.option("--header", "-H", multiple=True, help="Custom HTTP header (Name: Value).")
@click.option("--timeout", default=30, show_default=True)
@click.option("--verbose", "-v", is_flag=True, default=False)
def cmdinj(
    target: str, tool: str, param: str, base_value: str,
    no_enum: bool, lhost: str, lport: int,
    header: tuple[str, ...], timeout: int, verbose: bool,
) -> None:
    """Command injection exploiter for confirmed CMDi in MCP tools.

    \b
    Examples:
      mcpray cmdinj http://localhost:8000/mcp --tool run_cmd --param cmd
      mcpray cmdinj http://localhost:8000/mcp --tool exec --param command --lhost 10.0.0.1
    """
    _configure_logging(verbose)
    headers: dict[str, str] = {}
    for h in header:
        if ":" in h:
            k, _, v = h.partition(":")
            headers[k.strip()] = v.strip()
    asyncio.run(_run_cmdinj(target, tool, param, base_value, not no_enum, lhost, lport, headers, timeout))


async def _run_cmdinj(
    target: str, tool_name: str, param: str, base_value: str,
    enumerate_system: bool, lhost: str, lport: int,
    headers: dict, timeout: int,
) -> None:
    from .client import MCPClient
    from .scanners.cmdinj import CmdInjExploiter

    console.print(Panel(
        f"[bold]Target:[/]  {target}\n"
        f"[bold]Tool:[/]    {tool_name}\n"
        f"[bold]Param:[/]   {param}",
        title="[bold red]mcpray — CMDi Exploiter[/]",
        border_style="red", padding=(0, 2),
    ))
    console.print()

    async with MCPClient(target, headers=headers, timeout=timeout) as client:
        exploiter = CmdInjExploiter(client)
        with console.status("[cyan]Probing for command injection...[/]"):
            result = await exploiter.run(
                tool_name=tool_name, param=param, base_value=base_value,
                enumerate_system=enumerate_system, lhost=lhost, lport=lport,
            )

    if not result.confirmed:
        console.print(Panel("[yellow]Not injectable.[/]", border_style="yellow"))
        return

    console.print(Panel(
        f"[bold green]CONFIRMED[/]  technique: [bold]{result.technique}[/]\n"
        f"[bold]OS:[/]      {result.os_type or 'unknown'}\n"
        f"[bold]whoami:[/]  {result.whoami or '[dim]N/A[/]'}\n"
        f"[bold]id:[/]      {result.id_output or '[dim]N/A[/]'}\n"
        f"[bold]hostname:[/] {result.hostname or '[dim]N/A[/]'}",
        title="[bold red]Command Injection Confirmed[/]",
        border_style="red",
    ))
    console.print()

    if result.interesting_files:
        for path, content in result.interesting_files.items():
            console.print(Panel(
                content[:500], title=f"[bold]{path}[/]", border_style="yellow", padding=(0, 1)
            ))

    if result.reverse_shells:
        console.print("[bold]Reverse Shell Payloads:[/]")
        for i, shell in enumerate(result.reverse_shells, 1):
            console.print(f"  [dim]{i}.[/] {shell}")

    if result.error:
        console.print(f"[yellow]Note:[/] {result.error}")


# ─── ssrf-exploit ─────────────────────────────────────────────────────────────

@main.command("ssrf-exploit")
@click.argument("target")
@click.option("--tool", "-t", required=True, help="Tool name with the SSRF parameter.")
@click.option("--param", "-p", required=True, help="Parameter that accepts URLs.")
@click.option("--no-cloud", is_flag=True, default=False, help="Skip cloud metadata probing.")
@click.option("--no-internal", is_flag=True, default=False, help="Skip internal port scanning.")
@click.option("--header", "-H", multiple=True)
@click.option("--timeout", default=30, show_default=True)
@click.option("--verbose", "-v", is_flag=True, default=False)
def ssrf_exploit(
    target: str, tool: str, param: str, no_cloud: bool, no_internal: bool,
    header: tuple[str, ...], timeout: int, verbose: bool,
) -> None:
    """SSRF exploiter — pivot through a confirmed SSRF to reach cloud metadata and internal services.

    \b
    Examples:
      mcpray ssrf-exploit http://localhost:8000/mcp --tool fetch_url --param url
    """
    _configure_logging(verbose)
    headers: dict[str, str] = {}
    for h in header:
        if ":" in h:
            k, _, v = h.partition(":")
            headers[k.strip()] = v.strip()
    asyncio.run(_run_ssrf_exploit(target, tool, param, not no_cloud, not no_internal, headers, timeout))


async def _run_ssrf_exploit(
    target: str, tool_name: str, param: str, probe_cloud: bool,
    probe_internal: bool, headers: dict, timeout: int,
) -> None:
    from .client import MCPClient
    from .scanners.ssrf_exploit import SsrfExploiter

    console.print(Panel(
        f"[bold]Target:[/]  {target}\n"
        f"[bold]Tool:[/]    {tool_name}  param: [bold]{param}[/]",
        title="[bold red]mcpray — SSRF Exploiter[/]",
        border_style="red", padding=(0, 2),
    ))

    async with MCPClient(target, headers=headers, timeout=timeout) as client:
        exploiter = SsrfExploiter(client)
        with console.status("[cyan]Probing SSRF...[/]"):
            result = await exploiter.run(
                tool_name=tool_name, param=param,
                probe_cloud=probe_cloud, probe_internal=probe_internal,
            )

    if result.cloud_provider:
        console.print(f"\n[bold green]Cloud provider:[/] {result.cloud_provider}")
        for key, content in result.cloud_metadata.items():
            console.print(Panel(content[:400], title=f"[bold]{key}[/]", border_style="yellow", padding=(0,1)))

    if result.cloud_credentials:
        console.print("\n[bold red]Credentials extracted:[/]")
        for key, val in result.cloud_credentials.items():
            console.print(f"  [bold]{key}:[/] {val[:80]}")

    if result.internal_ports:
        console.print(f"\n[bold]Reachable internal endpoints:[/]")
        for ep in result.internal_ports:
            console.print(f"  [green]✓[/] {ep}")

    if result.kubernetes_exposed:
        console.print("\n[bold red]Kubernetes API reachable![/]")

    if result.error and not result.cloud_provider and not result.internal_ports:
        console.print(f"[yellow]No SSRF data retrieved:[/] {result.error}")


# ─── fuzz ─────────────────────────────────────────────────────────────────────

@main.command()
@click.argument("target")
@click.option("--max-cases", default=None, type=int,
              help="Limit number of fuzz cases (default: all ~38).")
@click.option("--timeout", default=10, show_default=True)
@click.option("--verbose", "-v", is_flag=True, default=False)
def fuzz(target: str, max_cases: int | None, timeout: int, verbose: bool) -> None:
    """Protocol fuzzer — send malformed JSON-RPC to find parser bugs and info leaks.

    \b
    Examples:
      mcpray fuzz http://localhost:8000/mcp
      mcpray fuzz http://localhost:8000/mcp --max-cases 20
    """
    _configure_logging(verbose)
    asyncio.run(_run_fuzz(target, max_cases, timeout))


async def _run_fuzz(target: str, max_cases: int | None, timeout: int) -> None:
    from .scanners.fuzzer import ProtocolFuzzer

    console.print(Panel(
        f"[bold]Target:[/] {target}",
        title="[bold red]mcpray — Protocol Fuzzer[/]",
        border_style="red", padding=(0, 2),
    ))
    console.print()

    fuzzer = ProtocolFuzzer(target, timeout=timeout)
    with console.status("[cyan]Fuzzing MCP protocol...[/]"):
        result = await fuzzer.run(max_cases=max_cases)

    console.print(f"[dim]Cases run: {result.total_cases}  Error rate: {result.error_rate:.1%}[/]")
    console.print()

    if not result.findings:
        console.print(Panel("[green]No anomalies detected.[/]", border_style="green"))
        return

    console.print(Panel(
        f"[bold red]{len(result.findings)} anomalies found[/]"
        + ("[bold red]  CRASH DETECTED[/]" if result.crash_detected else ""),
        border_style="red",
    ))

    tbl = Table(box=box.ROUNDED, padding=(0, 1))
    tbl.add_column("Case", style="dim", width=20)
    tbl.add_column("Category", width=18)
    tbl.add_column("Severity", width=10)
    tbl.add_column("Anomaly", width=20)
    tbl.add_column("Status", width=6)
    tbl.add_column("Snippet")

    for f in result.findings:
        sev_style = _SEVERITY_STYLE.get(f.severity, "")
        tbl.add_row(
            f.case_id, f.category,
            Text(f.severity, style=sev_style),
            f.anomaly_type, str(f.status_code),
            f.response_snippet[:50],
        )
    console.print(tbl)

    if result.info_leaks:
        console.print("\n[bold red]Info leaks detected:[/]")
        for leak in result.info_leaks[:5]:
            console.print(f"  [red]▸[/] {leak[:100]}")


# ─── graph ────────────────────────────────────────────────────────────────────

@main.command()
@click.argument("target")
@click.option("--output", "-o", default=None, help="Write Mermaid diagram to file.")
@click.option("--header", "-H", multiple=True)
@click.option("--timeout", default=30, show_default=True)
@click.option("--verbose", "-v", is_flag=True, default=False)
def graph(target: str, output: str | None, header: tuple[str, ...], timeout: int, verbose: bool) -> None:
    """Attack graph generator — map MCP tool/resource dependencies and highlight exploitation chains.

    \b
    Examples:
      mcpray graph http://localhost:8000/mcp
      mcpray graph http://localhost:8000/mcp --output attack_graph.mmd
    """
    _configure_logging(verbose)
    headers: dict[str, str] = {}
    for h in header:
        if ":" in h:
            k, _, v = h.partition(":")
            headers[k.strip()] = v.strip()
    asyncio.run(_run_graph(target, output, headers, timeout))


async def _run_graph(target: str, output: str | None, headers: dict, timeout: int) -> None:
    from .client import MCPClient
    from .scanners.attack_graph import AttackGraphBuilder

    async with MCPClient(target, headers=headers, timeout=timeout) as client:
        with console.status("[cyan]Enumerating inventory...[/]"):
            inventory = await client.get_inventory()

    builder = AttackGraphBuilder()
    result = builder.run(inventory)

    console.print(Panel(
        f"[bold]Nodes:[/]  {len(result.nodes)}\n"
        f"[bold]Edges:[/]  {len(result.edges)}\n"
        f"[bold]Attack paths:[/] {len(result.attack_paths)}",
        title="[bold red]Attack Graph[/]",
        border_style="red", padding=(0, 2),
    ))

    if result.attack_paths:
        console.print("\n[bold]Attack Paths:[/]")
        for i, path in enumerate(result.attack_paths, 1):
            sev_style = _SEVERITY_STYLE.get(path.severity, "bold")
            console.print(f"\n  [{sev_style}]{i}. [{path.severity}] {path.description}[/]")
            console.print(f"     Entry: [bold]{path.entry_point}[/] → Sink: [bold]{path.sink}[/]")
            console.print(f"     Path:  {' → '.join(path.nodes[:6])}")

    high_risk = [n for n in result.nodes if n.risk_score >= 7.0]
    if high_risk:
        console.print("\n[bold]High-risk nodes:[/]")
        for n in sorted(high_risk, key=lambda x: -x.risk_score)[:8]:
            style = "bold red" if n.risk_score >= 9 else "bold dark_orange"
            console.print(f"  [{style}]{n.risk_score:.1f}[/] [bold]{n.name}[/] [dim]— {n.risk_reason[:60]}[/]")

    if output:
        Path(output).write_text(result.mermaid_diagram)
        console.print(f"\n[green]✓[/] Mermaid diagram written: {output}")
    else:
        console.print("\n[dim]Use --output FILE to save the Mermaid diagram.[/]")


# ─── taint ────────────────────────────────────────────────────────────────────

@main.command()
@click.argument("target")
@click.option("--header", "-H", multiple=True)
@click.option("--timeout", default=30, show_default=True)
@click.option("--verbose", "-v", is_flag=True, default=False)
def taint(target: str, header: tuple[str, ...], timeout: int, verbose: bool) -> None:
    """Data flow taint analyzer — static analysis of tool schemas to trace user input to sinks.

    \b
    Examples:
      mcpray taint http://localhost:8000/mcp
    """
    _configure_logging(verbose)
    headers: dict[str, str] = {}
    for h in header:
        if ":" in h:
            k, _, v = h.partition(":")
            headers[k.strip()] = v.strip()
    asyncio.run(_run_taint(target, headers, timeout))


async def _run_taint(target: str, headers: dict, timeout: int) -> None:
    from .client import MCPClient
    from .scanners.dataflow import DataFlowAnalyzer

    async with MCPClient(target, headers=headers, timeout=timeout) as client:
        with console.status("[cyan]Enumerating inventory...[/]"):
            inventory = await client.get_inventory()

    analyzer = DataFlowAnalyzer()
    result = analyzer.run(inventory)

    console.print(Panel(
        f"[bold]Sources (injectable params):[/] {len(result.sources)}\n"
        f"[bold]Sinks (dangerous operations):[/] {len(result.sinks)}\n"
        f"[bold]Taint flows:[/] {len(result.flows)}\n"
        f"[bold red]Critical flows:[/] {len(result.critical_flows)}",
        title="[bold red]Data Flow Analysis[/]",
        border_style="red", padding=(0, 2),
    ))

    if result.flows:
        tbl = Table(title="Taint Flows", box=box.ROUNDED, padding=(0, 1))
        tbl.add_column("Severity", width=10)
        tbl.add_column("Source Tool", width=20)
        tbl.add_column("Param", width=16)
        tbl.add_column("Sink Category", width=18)
        tbl.add_column("CWE", width=10)
        tbl.add_column("Description")

        for flow in sorted(result.flows, key=lambda f: f.severity)[:30]:
            sev_style = _SEVERITY_STYLE.get(flow.severity, "")
            tbl.add_row(
                Text(flow.severity, style=sev_style),
                flow.source.tool_name[:18],
                flow.source.param_name[:14],
                flow.sink.sink_category[:16],
                flow.cwe_id,
                flow.path_description[:50],
            )
        console.print(tbl)


# ─── mitm ─────────────────────────────────────────────────────────────────────

@main.command()
@click.argument("target")
@click.option("--listen-port", default=19080, show_default=True,
              help="Local port for the proxy to listen on.")
@click.option("--listen-host", default="127.0.0.1", show_default=True)
@click.option("--output", "-o", default=None, help="Save session JSON to this file on exit.")
@click.option("--tamper-tool", default=None, help="Tool name to tamper with (for --tamper-param).")
@click.option("--tamper-param", default=None, help="Parameter name to replace.")
@click.option("--tamper-value", default=None, help="Replacement value for --tamper-param.")
@click.option("--verbose", "-v", is_flag=True, default=False)
def mitm(
    target: str, listen_port: int, listen_host: str,
    output: str | None, tamper_tool: str | None, tamper_param: str | None,
    tamper_value: str | None, verbose: bool,
) -> None:
    """MCP MITM proxy — intercept and log all JSON-RPC traffic between client and server.

    Point your MCP client at the proxy URL instead of the real server.

    \b
    Examples:
      mcpray mitm http://localhost:8000/mcp
      mcpray mitm http://localhost:8000/mcp --listen-port 18080 --output session.json
      mcpray mitm http://target/mcp --tamper-tool exec --tamper-param cmd --tamper-value "id"
    """
    from .scanners.mitm import MCPMitmProxy, create_logging_interceptor, create_tamper_interceptor

    interceptors = []
    if output:
        log_path = output.replace(".json", ".jsonl")
        interceptors.append(create_logging_interceptor(log_path))
        console.print(f"[dim]JSONL log: {log_path}[/]")

    if tamper_tool and tamper_param and tamper_value:
        interceptors.append(create_tamper_interceptor(tamper_tool, tamper_param, tamper_value))
        console.print(f"[yellow]Tamper:[/] {tamper_tool}.{tamper_param} → {tamper_value!r}")

    def _combined_interceptor(exchange):
        for fn in interceptors:
            exchange = fn(exchange)
            if exchange is None:
                return None
        return exchange

    intercept_fn = _combined_interceptor if interceptors else None

    proxy = MCPMitmProxy(
        upstream=target,
        listen_host=listen_host,
        listen_port=listen_port,
        verbose=verbose,
        intercept=intercept_fn,
    )
    proxy_url = proxy.start()

    console.print(Panel(
        f"[bold]Upstream:[/]  {target}\n"
        f"[bold]Proxy URL:[/] [bold cyan]{proxy_url}[/]\n\n"
        f"Point your MCP client at [bold cyan]{proxy_url}[/] instead of the real server.\n"
        f"Press [bold]Ctrl+C[/] to stop.",
        title="[bold green]MCP MITM Proxy Running[/]",
        border_style="green", padding=(0, 2),
    ))
    console.print()

    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        proxy.stop()
        console.print()
        proxy.print_summary()

        findings = proxy.get_interesting_findings()
        if findings:
            console.print("\n[bold red]Security findings from captured traffic:[/]")
            for f in findings:
                console.print(f"  [red]▸[/] {f}")

        if output:
            proxy.save_session(output)
            console.print(f"\n[green]✓[/] Session saved: {output}")


# ─── nuclei ───────────────────────────────────────────────────────────────────

@main.command()
@click.argument("json_file")
@click.option("--output-dir", "-o", default=".", show_default=True,
              help="Directory to write Nuclei templates into.")
@click.option("--min-severity", default="MEDIUM",
              type=click.Choice(["INFORMATIONAL","LOW","MEDIUM","HIGH","CRITICAL"], case_sensitive=False),
              help="Minimum severity to include.")
@click.option("--pack", is_flag=True, default=False, help="Also create a .zip pack of all templates.")
def nuclei(json_file: str, output_dir: str, min_severity: str, pack: bool) -> None:
    """Generate Nuclei YAML templates from a saved mcpray JSON scan result.

    \b
    Examples:
      mcpray nuclei results.json
      mcpray nuclei results.json --output-dir ./nuclei_templates --min-severity HIGH
      mcpray nuclei results.json --pack
    """
    from .reporters.nuclei_reporter import generate_nuclei_templates, save_nuclei_pack
    from .findings import Severity

    result = _reconstruct_result(json.loads(Path(json_file).read_text()))
    min_sev = Severity(min_severity.upper())

    paths = generate_nuclei_templates(result, output_dir, min_severity=min_sev)
    if paths:
        console.print(f"[green]✓[/] {len(paths)} Nuclei template(s) written to {output_dir}/nuclei_templates/")
        for p in paths[:10]:
            console.print(f"  [dim]{p}[/]")
        if len(paths) > 10:
            console.print(f"  [dim]... and {len(paths)-10} more[/]")
    else:
        console.print("[yellow]No qualifying findings for Nuclei templates.[/]")
        return

    if pack:
        zip_path = save_nuclei_pack(result, output_dir, min_severity=min_sev)
        console.print(f"[green]✓[/] Pack: {zip_path}")

    console.print(f"\n[dim]Run with: nuclei -t {output_dir}/nuclei_templates/ -u {result.server_inventory.target}[/]")


# ─── poc ──────────────────────────────────────────────────────────────────────

@main.command()
@click.argument("json_file")
@click.option("--output-dir", "-o", default=".", show_default=True,
              help="Directory to write PoC scripts into.")
@click.option("--min-severity", default="HIGH",
              type=click.Choice(["INFORMATIONAL","LOW","MEDIUM","HIGH","CRITICAL"], case_sensitive=False))
@click.option("--bundle", is_flag=True, default=False,
              help="Also generate a single combined PoC bundle script.")
def poc(json_file: str, output_dir: str, min_severity: str, bundle: bool) -> None:
    """Generate runnable Python PoC exploit scripts from a saved mcpray JSON scan result.

    \b
    Examples:
      mcpray poc results.json
      mcpray poc results.json --min-severity CRITICAL --bundle
    """
    from .reporters.poc_generator import generate_all_pocs, generate_poc_bundle
    from .findings import Severity

    result = _reconstruct_result(json.loads(Path(json_file).read_text()))
    min_sev = Severity(min_severity.upper())

    paths = generate_all_pocs(result, output_dir, min_severity=min_sev)
    if paths:
        console.print(f"[green]✓[/] {len(paths)} PoC script(s) written to {output_dir}/pocs/")
        for p in paths[:10]:
            console.print(f"  [dim]{p}[/]")
    else:
        console.print("[yellow]No qualifying findings for PoC generation.[/]")
        return

    if bundle:
        bundle_path = generate_poc_bundle(result, output_dir)
        console.print(f"[green]✓[/] Bundle: {bundle_path}")


# ─── install-completion ───────────────────────────────────────────────────────

@main.command("install-completion")
@click.option(
    "--shell",
    type=click.Choice(["bash", "zsh", "fish"], case_sensitive=False),
    default=None,
    help="Shell type. Auto-detected from $SHELL if omitted.",
)
@click.option(
    "--append", is_flag=True, default=False,
    help="Automatically append the eval line to your shell config file.",
)
def install_completion(shell: str | None, append: bool) -> None:
    """Install Tab-completion for all mcpray CLI commands and options.

    Enables Tab-completion for subcommands (scan, sqli, fuzz, …) and their
    options (--template, --param, …) directly in your shell.

    \b
    Quick setup:
      mcpray install-completion              # print the line for your shell
      mcpray install-completion --append     # auto-append to ~/.zshrc / ~/.bashrc
      mcpray install-completion --shell fish --append

    \b
    Manual setup:
      # zsh / bash
      eval "$(_MCPRAY_COMPLETE=zsh_source mcpray)"   # add to ~/.zshrc
      eval "$(_MCPRAY_COMPLETE=bash_source mcpray)"  # add to ~/.bashrc

      # fish
      eval (env _MCPRAY_COMPLETE=fish_source mcpray) # add to ~/.config/fish/config.fish
    """
    import os
    import shutil

    # Auto-detect shell
    if shell is None:
        shell_path = os.environ.get("SHELL", "")
        if "zsh" in shell_path:
            shell = "zsh"
        elif "fish" in shell_path:
            shell = "fish"
        else:
            shell = "bash"

    shell = shell.lower()

    # Build eval line and config file path
    env_key = f"_MCPRAY_COMPLETE={shell}_source"
    if shell == "fish":
        eval_line = f"eval (env {env_key} mcpray)"
        config_file = Path.home() / ".config" / "fish" / "config.fish"
    elif shell == "zsh":
        eval_line = f'eval "$({env_key} mcpray)"'
        config_file = Path.home() / ".zshrc"
    else:
        eval_line = f'eval "$({env_key} mcpray)"'
        config_file = Path.home() / ".bashrc"

    # Check that mcpray is on PATH (needed for shell completion to work)
    mcpray_path = shutil.which("mcpray")
    path_note = (
        f"[green]mcpray found:[/] {mcpray_path}"
        if mcpray_path
        else "[yellow]mcpray not on PATH — install with: pip install -e .[/]"
    )

    console.print(Panel(
        f"[bold]Shell:[/]       {shell}\n"
        f"[bold]Config file:[/] {config_file}\n"
        f"{path_note}\n\n"
        f"[bold]Add this line to [cyan]{config_file}[/]:[/]\n\n"
        f"  [bold green]{eval_line}[/]\n\n"
        f"[dim]Then restart your shell or run:[/]  source {config_file}",
        title="[bold cyan]Shell Tab-Completion Setup[/]",
        border_style="cyan",
        padding=(0, 2),
    ))

    if append:
        try:
            config_file.parent.mkdir(parents=True, exist_ok=True)
            existing = config_file.read_text() if config_file.exists() else ""
            if eval_line in existing:
                console.print("[yellow]Already present in config file — nothing added.[/]")
            else:
                with config_file.open("a") as f:
                    f.write(f"\n# mcpray tab-completion\n{eval_line}\n")
                console.print(f"[green]✓[/] Appended to [bold]{config_file}[/]")
                console.print(f"[dim]Activate now:[/]  source {config_file}")
        except OSError as e:
            console.print(f"[red]Could not write to {config_file}:[/] {e}")
            console.print(f"[dim]Add manually:[/] {eval_line}")


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _print_header(target: str, active: bool) -> None:
    console.print()
    console.print(
        Panel(
            f"[bold]Target:[/]  {target}\n"
            f"[bold]Mode:[/]    {'Active + Passive' if active else 'Passive (read-only)'}",
            title="[bold cyan]mcpray v1.0.0 — MCP Security Scanner[/]",
            border_style="cyan",
            padding=(0, 2),
        )
    )
    console.print()


async def _run_with_progress(
    target: str, active: bool, headers: dict, timeout: int, rules: str | None
) -> ScanResult:
    stages = [
        "Probing authentication...",
        "Enumerating inventory (tools, resources, prompts)...",
        "Running auth checks...",
        "Analyzing tool security...",
        "Scanning resources...",
        "Checking prompt injection surfaces...",
    ]
    if active:
        stages.append("Running active probes...")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Connecting...", total=None)
        for stage in stages:
            progress.update(task, description=stage)
            await asyncio.sleep(0)  # yield to event loop
        result = await run_scan(target, active=active, headers=headers,
                                timeout=timeout, custom_rules=rules)
    return result


def _print_results(result: ScanResult) -> None:
    inv = result.server_inventory
    sev_counts = Counter(f.severity.value for f in result.findings)

    # Inventory summary
    inv_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    inv_table.add_column(style="dim")
    inv_table.add_column(style="bold")
    inv_table.add_row("Target", inv.target)
    inv_table.add_row("Transport", inv.transport)
    inv_table.add_row("Auth Required", "Yes" if inv.auth_required else "[bold red]No (Anonymous Access!)[/]")
    inv_table.add_row("Tools", str(len(inv.tools)))
    inv_table.add_row("Resources", str(len(inv.resources)))
    inv_table.add_row("Templates", str(len(inv.resource_templates)))
    inv_table.add_row("Prompts", str(len(inv.prompts)))
    console.print(inv_table)

    # Risk banner
    risk_style = _SEVERITY_STYLE.get(result.risk_level.value, "bold")
    console.print(
        Panel(
            f"[{risk_style}]Overall Risk: {result.risk_level.value}  ({result.overall_risk_score:.1f}/10)[/]\n"
            f"[red]Critical: {sev_counts.get('CRITICAL', 0)}[/]  "
            f"[dark_orange]High: {sev_counts.get('HIGH', 0)}[/]  "
            f"[yellow]Medium: {sev_counts.get('MEDIUM', 0)}[/]  "
            f"[green]Low: {sev_counts.get('LOW', 0)}[/]  "
            f"[dim]Info: {sev_counts.get('INFORMATIONAL', 0)}[/]",
            border_style=risk_style.split()[-1] if " " in risk_style else risk_style,
        )
    )
    console.print()

    # Findings table
    if result.findings:
        table = Table(title="Findings", box=box.ROUNDED, show_lines=False, padding=(0, 1))
        table.add_column("ID", style="dim", width=12)
        table.add_column("Severity", width=10)
        table.add_column("Score", justify="right", width=6)
        table.add_column("Title")
        table.add_column("Component")

        for f in result.findings:
            style = _SEVERITY_STYLE.get(f.severity.value, "")
            table.add_row(
                f.id,
                Text(f.severity.value, style=style),
                f"{f.risk_score:.1f}",
                f.title[:70],
                f.affected_component[:40],
            )
        console.print(table)
        console.print()

    # Attack paths
    if result.attack_paths:
        console.print("[bold]Attack Paths Identified:[/]")
        for i, path in enumerate(result.attack_paths, 1):
            console.print(f"  {i}. [bold]{path.name}[/] [dim]({path.likelihood})[/]")
            for j, step in enumerate(path.steps[:4], 1):
                prefix = "    └─" if j == min(4, len(path.steps)) else "    ├─"
                console.print(f"{prefix} {step}")
            if len(path.steps) > 4:
                console.print(f"    └─ ... ({len(path.steps) - 4} more steps)")
            console.print()

    # Top tool abuse factors
    high_risk_tools = [t for t in result.tool_abuse_factors if t.risk_score >= 7.0]
    if high_risk_tools:
        console.print("[bold]High-Risk Tool Abuse Factors:[/]")
        for t in high_risk_tools[:5]:
            style = "bold red" if t.risk_score >= 9 else "bold dark_orange" if t.risk_score >= 7 else "yellow"
            cats = ", ".join(c.value for c in t.abuse_categories[:3])
            console.print(
                f"  [{style}]{t.risk_score:.1f}[/] [bold]{t.tool_name}[/] [dim]— {cats}[/]"
            )


def _print_summary_line(result: ScanResult) -> None:
    sev_counts = Counter(f.severity.value for f in result.findings)
    style = _SEVERITY_STYLE.get(result.risk_level.value, "")
    console.print(
        f"  [{style}]{result.risk_level.value} ({result.overall_risk_score:.1f})[/] "
        f"C:{sev_counts.get('CRITICAL',0)} H:{sev_counts.get('HIGH',0)} "
        f"M:{sev_counts.get('MEDIUM',0)} L:{sev_counts.get('LOW',0)}"
    )


def _safe_stem(target: str) -> str:
    return (
        target.replace("https://", "")
        .replace("http://", "")
        .replace("/", "_")
        .replace(":", "-")
        .strip("_")[:50]
    )


def _reconstruct_result(data: dict) -> ScanResult:
    """Reconstruct a ScanResult from a saved JSON dict (best-effort)."""
    from .findings import Finding, Severity, AbuseCategory, ToolAbuseFactor, AttackPath, ServerInventory, ScanResult

    meta = data.get("meta", {})
    inv_data = data.get("server_inventory", {})

    inventory = ServerInventory(
        target=inv_data.get("target", meta.get("target", "")),
        transport=inv_data.get("transport", "UNKNOWN"),
        auth_required=inv_data.get("auth_required", False),
        tools=inv_data.get("tools", []),
        resources=inv_data.get("resources", []),
        resource_templates=inv_data.get("resource_templates", []),
        prompts=inv_data.get("prompts", []),
    )

    findings = []
    for fd in data.get("findings", []):
        findings.append(Finding(
            id=fd["id"],
            title=fd["title"],
            severity=Severity(fd["severity"]),
            affected_component=fd["affected_component"],
            evidence=fd["evidence"],
            reproduction_steps=fd.get("reproduction_steps", []),
            impact=fd["impact"],
            remediation=fd["remediation"],
            abuse_categories=[AbuseCategory(c) for c in fd.get("abuse_categories", []) if c in AbuseCategory._value2member_map_],
            risk_score=fd.get("risk_score", 0.0),
            tags=fd.get("tags", []),
        ))

    abuse_factors = []
    for af in data.get("tool_abuse_factors", []):
        abuse_factors.append(ToolAbuseFactor(
            tool_name=af["tool_name"],
            risk_score=af["risk_score"],
            abuse_categories=[AbuseCategory(c) for c in af.get("abuse_categories", []) if c in AbuseCategory._value2member_map_],
            attack_vectors=af.get("attack_vectors", []),
            dangerous_params=af.get("dangerous_params", []),
        ))

    attack_paths = []
    for ap in data.get("attack_paths", []):
        attack_paths.append(AttackPath(
            name=ap["name"],
            steps=ap["steps"],
            prerequisites=ap.get("prerequisites", []),
            impact=ap["impact"],
            likelihood=ap.get("likelihood", "MEDIUM"),
            related_findings=ap.get("related_findings", []),
        ))

    return ScanResult(
        target=meta.get("target", ""),
        scan_timestamp=meta.get("scan_timestamp", ""),
        scanner_version=meta.get("scanner_version", "1.0.0"),
        findings=findings,
        tool_abuse_factors=abuse_factors,
        server_inventory=inventory,
        attack_paths=attack_paths,
        overall_risk_score=meta.get("overall_risk_score", 0.0),
        risk_level=Severity(meta.get("risk_level", "INFORMATIONAL")),
        active_testing_enabled=meta.get("active_testing_enabled", False),
    )
