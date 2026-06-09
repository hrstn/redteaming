"""Protocol analysis REPL command handlers: fuzz, graph, taint, mitm."""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel

if TYPE_CHECKING:
    from ..state import REPLState


# ─── fuzz ─────────────────────────────────────────────────────────────────────

async def cmd_fuzz(state: "REPLState", args: list[str], console: Console) -> None:
    """Protocol fuzzer — send malformed JSON-RPC to detect parser bugs.

    Usage:
      fuzz
      fuzz --max-cases 20
    """
    from ...scanners.fuzzer import ProtocolFuzzer
    from rich.table import Table as _Table
    from rich import box as _box

    max_cases: int | None = None
    for i, a in enumerate(args):
        if a == "--max-cases" and i + 1 < len(args):
            try:
                max_cases = int(args[i + 1])
            except ValueError:
                pass

    fuzzer = ProtocolFuzzer(state.target, timeout=10)
    with console.status("[cyan]Fuzzing MCP protocol...[/]"):
        result = await fuzzer.run(max_cases=max_cases)

    console.print(
        f"[dim]Cases: {result.total_cases}  Error rate: {result.error_rate:.1%}"
        + ("  [bold red]CRASH DETECTED[/]" if result.crash_detected else "") + "[/]"
    )

    if not result.findings:
        console.print("[green]✓ No anomalies detected.[/]")
        return

    tbl = _Table(title=f"{len(result.findings)} anomalies", box=_box.SIMPLE, padding=(0, 1))
    tbl.add_column("Category", width=18)
    tbl.add_column("Severity", width=10)
    tbl.add_column("Anomaly", width=20)
    tbl.add_column("Status", width=6)
    tbl.add_column("Snippet")
    for f in result.findings:
        tbl.add_row(f.category, f.severity, f.anomaly_type,
                    str(f.status_code), f.response_snippet[:60])
    console.print(tbl)


# ─── graph ────────────────────────────────────────────────────────────────────

async def cmd_graph(state: "REPLState", args: list[str], console: Console) -> None:
    """Attack graph — map tool/resource dependencies and highlight exploitation chains.

    Usage:
      graph
      graph --output attack.mmd
    """
    from ...scanners.attack_graph import AttackGraphBuilder

    if not state.require_scan():
        console.print("[yellow]Run: scan[/]")
        return

    output: str | None = None
    for i, a in enumerate(args):
        if a == "--output" and i + 1 < len(args):
            output = args[i + 1]

    builder = AttackGraphBuilder()
    result = builder.run(state.scan_result.server_inventory)

    console.print(Panel(
        f"[bold]Nodes:[/] {len(result.nodes)}  [bold]Edges:[/] {len(result.edges)}\n"
        f"[bold red]Attack paths:[/] {len(result.attack_paths)}",
        title="[bold red]Attack Graph[/]", border_style="red",
    ))

    for i, path in enumerate(result.attack_paths, 1):
        sev_map = {"CRITICAL": "bold red", "HIGH": "bold dark_orange", "MEDIUM": "bold yellow"}
        style = sev_map.get(path.severity, "bold")
        console.print(f"\n  [{style}]{i}. [{path.severity}][/] {path.description}")
        console.print(f"     [dim]{' → '.join(path.nodes[:6])}[/]")

    high_risk = sorted([n for n in result.nodes if n.risk_score >= 7.0],
                       key=lambda x: -x.risk_score)[:6]
    if high_risk:
        console.print("\n[bold]High-risk nodes:[/]")
        for n in high_risk:
            style = "bold red" if n.risk_score >= 9 else "bold dark_orange"
            console.print(f"  [{style}]{n.risk_score:.1f}[/] {n.name}  [dim]{n.risk_reason[:60]}[/]")

    if output:
        from pathlib import Path
        Path(output).write_text(result.mermaid_diagram)
        console.print(f"\n[green]✓[/] Mermaid diagram: {output}")
    else:
        console.print("\n[dim]Use: graph --output FILE to save Mermaid diagram[/]")


# ─── taint ────────────────────────────────────────────────────────────────────

async def cmd_taint(state: "REPLState", args: list[str], console: Console) -> None:
    """Data flow taint analysis — static trace of user inputs to dangerous sinks.

    Usage:
      taint
    """
    from ...scanners.dataflow import DataFlowAnalyzer
    from rich.table import Table as _Table
    from rich import box as _box

    if not state.require_scan():
        console.print("[yellow]Run: scan[/]")
        return

    analyzer = DataFlowAnalyzer()
    result = analyzer.run(state.scan_result.server_inventory)

    console.print(Panel(
        f"Sources: {len(result.sources)}  Sinks: {len(result.sinks)}\n"
        f"[bold red]Flows: {len(result.flows)}  Critical: {len(result.critical_flows)}[/]",
        title="Taint Analysis", border_style="red",
    ))

    if result.flows:
        tbl = _Table(box=_box.SIMPLE, padding=(0, 1))
        tbl.add_column("Sev", width=10)
        tbl.add_column("Tool", width=18)
        tbl.add_column("Param", width=14)
        tbl.add_column("Category", width=18)
        tbl.add_column("CWE", width=10)
        for flow in sorted(result.flows, key=lambda f: f.severity)[:20]:
            tbl.add_row(flow.severity, flow.source.tool_name[:16],
                        flow.source.param_name[:12], flow.sink.sink_category[:16], flow.cwe_id)
        console.print(tbl)


# ─── mitm ─────────────────────────────────────────────────────────────────────

async def cmd_mitm(state: "REPLState", args: list[str], console: Console) -> None:
    """Start a MITM proxy — intercept all MCP traffic.

    Usage:
      mitm
      mitm --port 18080
      mitm --port 18080 --output session.json
    """
    from ...scanners.mitm import MCPMitmProxy
    import time

    port = 19080
    output: str | None = None
    for i, a in enumerate(args):
        if a == "--port" and i + 1 < len(args):
            try:
                port = int(args[i + 1])
            except ValueError:
                pass
        elif a == "--output" and i + 1 < len(args):
            output = args[i + 1]

    proxy = MCPMitmProxy(upstream=state.target, listen_port=port)
    proxy_url = proxy.start()

    console.print(Panel(
        f"[bold]Upstream:[/] {state.target}\n"
        f"[bold]Proxy:[/]    [bold cyan]{proxy_url}[/]\n\n"
        "Press [bold]Enter[/] to stop.",
        title="[bold green]MITM Proxy Running[/]", border_style="green",
    ))

    await loop_until_enter()

    proxy.stop()
    proxy.print_summary()

    findings = proxy.get_interesting_findings()
    if findings:
        console.print("[bold red]Security findings:[/]")
        for f in findings:
            console.print(f"  [red]▸[/] {f}")

    if output:
        proxy.save_session(output)
        console.print(f"[green]✓[/] Session: {output}")


async def loop_until_enter():
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, input, "")


# ─── Command registry ─────────────────────────────────────────────────────────

COMMANDS: dict[str, tuple] = {
    "fuzz":  (cmd_fuzz,  "Protocol fuzzer (malformed JSON-RPC)"),
    "graph": (cmd_graph, "Attack graph generator"),
    "taint": (cmd_taint, "Data flow taint analyzer"),
    "mitm":  (cmd_mitm,  "Start MITM proxy to intercept MCP traffic"),
}
