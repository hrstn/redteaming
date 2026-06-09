"""Scan orchestration core for mcpray.

This module holds the execution/orchestration logic that drives the various
scanners (the full passive+active scan, discovery sweeps, the SQLi enumerator,
command-injection/SSRF exploiters, the protocol fuzzer, the attack-graph and
taint analyzers) and the helpers that render their structured results.

``cli.py`` is kept as thin Click routing: it parses arguments, calls one of the
``run_*`` coroutines here, and lets these functions format the output. The
``Console`` instance is passed in by the CLI so behaviour such as ``--no-color``
is preserved.

``run_scan`` is re-exported from here so ``from mcpray.runner import run_scan``
works alongside the canonical implementation in ``scanner.py``.
"""

from __future__ import annotations

import asyncio
import json
from collections import Counter
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import box
from rich.text import Text

from .findings import Severity, ScanResult
from .scanner import run_scan  # re-exported; canonical orchestration of scanners

__all__ = [
    "run_scan",
    "run_scan_with_progress",
    "run_discover",
    "run_sqli",
    "run_cmdinj",
    "run_ssrf_exploit",
    "run_fuzz",
    "run_graph",
    "run_taint",
    "print_header",
    "print_results",
    "print_summary_line",
    "print_discovery_results",
    "reconstruct_result",
    "safe_stem",
    "SEVERITY_STYLE",
]

SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH": "bold dark_orange",
    "MEDIUM": "bold yellow",
    "LOW": "bold green",
    "INFORMATIONAL": "dim",
}

SEV_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
             Severity.LOW: 3, Severity.INFORMATIONAL: 4}


# ─── Full scan ──────────────────────────────────────────────────────────────

async def run_scan_with_progress(
    console: Console,
    target: str,
    active: bool,
    headers: dict,
    timeout: int,
    rules: str | None,
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


def print_header(console: Console, target: str, active: bool) -> None:
    from . import __version__

    console.print()
    console.print(
        Panel(
            f"[bold]Target:[/]  {target}\n"
            f"[bold]Mode:[/]    {'Active + Passive' if active else 'Passive (read-only)'}",
            title=f"[bold cyan]mcpray v{__version__} — MCP Security Scanner[/]",
            border_style="cyan",
            padding=(0, 2),
        )
    )
    console.print()


def print_results(console: Console, result: ScanResult) -> None:
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
    risk_style = SEVERITY_STYLE.get(result.risk_level.value, "bold")
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
            style = SEVERITY_STYLE.get(f.severity.value, "")
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


def print_summary_line(console: Console, result: ScanResult) -> None:
    sev_counts = Counter(f.severity.value for f in result.findings)
    style = SEVERITY_STYLE.get(result.risk_level.value, "")
    console.print(
        f"  [{style}]{result.risk_level.value} ({result.overall_risk_score:.1f})[/] "
        f"C:{sev_counts.get('CRITICAL',0)} H:{sev_counts.get('HIGH',0)} "
        f"M:{sev_counts.get('MEDIUM',0)} L:{sev_counts.get('LOW',0)}"
    )


def safe_stem(target: str) -> str:
    return (
        target.replace("https://", "")
        .replace("http://", "")
        .replace("/", "_")
        .replace(":", "-")
        .strip("_")[:50]
    )


# ─── Discovery ────────────────────────────────────────────────────────────────

async def run_discover(
    console: Console,
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

    print_discovery_results(console, result)

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


def print_discovery_results(console: Console, result) -> None:
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


# ─── SQLi ───────────────────────────────────────────────────────────────────

async def run_sqli(
    console: Console,
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


# ─── Command injection ────────────────────────────────────────────────────────

async def run_cmdinj(
    console: Console,
    target: str,
    tool_name: str,
    param: str,
    base_value: str,
    enumerate_system: bool,
    lhost: str,
    lport: int,
    headers: dict,
    timeout: int,
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


# ─── SSRF exploit ─────────────────────────────────────────────────────────────

async def run_ssrf_exploit(
    console: Console,
    target: str,
    tool_name: str,
    param: str,
    probe_cloud: bool,
    probe_internal: bool,
    headers: dict,
    timeout: int,
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
            console.print(Panel(content[:400], title=f"[bold]{key}[/]", border_style="yellow", padding=(0, 1)))

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


# ─── Protocol fuzzer ──────────────────────────────────────────────────────────

async def run_fuzz(console: Console, target: str, max_cases: int | None, timeout: int) -> None:
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
        sev_style = SEVERITY_STYLE.get(f.severity, "")
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


# ─── Attack graph ─────────────────────────────────────────────────────────────

async def run_graph(console: Console, target: str, output: str | None, headers: dict, timeout: int) -> None:
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
            sev_style = SEVERITY_STYLE.get(path.severity, "bold")
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


# ─── Taint analyzer ───────────────────────────────────────────────────────────

async def run_taint(console: Console, target: str, headers: dict, timeout: int) -> None:
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
            sev_style = SEVERITY_STYLE.get(flow.severity, "")
            tbl.add_row(
                Text(flow.severity, style=sev_style),
                flow.source.tool_name[:18],
                flow.source.param_name[:14],
                flow.sink.sink_category[:16],
                flow.cwe_id,
                flow.path_description[:50],
            )
        console.print(tbl)


# ─── Result reconstruction (for report / nuclei / poc) ─────────────────────────

def reconstruct_result(data: dict) -> ScanResult:
    """Reconstruct a ScanResult from a saved JSON dict (best-effort)."""
    from .findings import (
        Finding, Severity, AbuseCategory, ToolAbuseFactor, AttackPath,
        ServerInventory, ScanResult,
    )

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
