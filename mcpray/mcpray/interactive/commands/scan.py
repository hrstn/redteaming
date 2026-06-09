"""Scan-related REPL command handlers: scan, findings, show, verify."""
from __future__ import annotations

from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich import box
from rich.text import Text

from ...findings import Severity
from ...scanner import run_scan
from ...ai import logger as ai_logger

from ._shared import _SEV_STYLE, _ainput, _print_ai_analysis

if TYPE_CHECKING:
    from ..state import REPLState


# ─── scan ─────────────────────────────────────────────────────────────────────

async def cmd_scan(state: "REPLState", args: list[str], console: Console) -> None:
    active = "--active" in args
    deep = "--deep" in args
    if active:
        console.print("[yellow]Active mode — non-destructive probes will be sent.[/]")
        confirm = await _ainput("Confirm active scan? [y/N]: ")
        if confirm.strip().lower() != "y":
            console.print("[dim]Cancelled.[/]")
            return

    with console.status(f"[cyan]Scanning {state.target}...[/]"):
        try:
            result = await run_scan(
                state.target,
                active=active,
                headers=state.mcp_client.headers,
                timeout=state.mcp_client.timeout,
            )
        except Exception as e:
            console.print(f"[red]Scan error:[/] {e}")
            return

    state.scan_result = result
    state.ai_cache.clear()
    state.payload_cache.clear()

    from collections import Counter
    sc = Counter(f.severity.value for f in result.findings)
    sev_style = _SEV_STYLE.get(result.risk_level.value, "bold")
    console.print(
        Panel(
            f"[{sev_style}]Risk: {result.risk_level.value} ({result.overall_risk_score:.1f}/10)[/]\n"
            f"[red]C:{sc.get('CRITICAL',0)}[/] [dark_orange]H:{sc.get('HIGH',0)}[/] "
            f"[yellow]M:{sc.get('MEDIUM',0)}[/] [green]L:{sc.get('LOW',0)}[/]  "
            f"Total: {len(result.findings)} findings",
            title="Scan Complete",
            border_style="cyan",
        )
    )
    ai_logger.log_event("scan_complete", target=state.target, findings=len(result.findings),
                        risk=result.risk_level.value)


# ─── findings ─────────────────────────────────────────────────────────────────

async def cmd_findings(state: "REPLState", args: list[str], console: Console) -> None:
    if not state.require_scan():
        console.print("[yellow]No scan results yet. Run: scan[/]")
        return

    page = 1
    page_size = 20
    for a in args:
        if a.startswith("--page="):
            try:
                page = int(a.split("=")[1])
            except ValueError:
                pass

    findings = state.scan_result.findings
    total = len(findings)
    start = (page - 1) * page_size
    end = start + page_size
    page_findings = findings[start:end]

    t = Table(title=f"Findings ({total} total)", box=box.ROUNDED, show_lines=False, padding=(0, 1))
    t.add_column("#", style="dim", width=4, justify="right")
    t.add_column("ID", width=12)
    t.add_column("Sev", width=10)
    t.add_column("Score", justify="right", width=6)
    t.add_column("Title")
    t.add_column("AI", width=4, justify="center")

    for i, f in enumerate(page_findings, start + 1):
        sev_style = _SEV_STYLE.get(f.severity.value, "")
        ai_marker = "✓" if f.ai_analysis else ""
        t.add_row(
            str(i),
            f.id,
            Text(f.severity.value, style=sev_style),
            f"{f.risk_score:.1f}",
            f.title[:60],
            Text(ai_marker, style="green"),
        )

    console.print(t)
    if total > end:
        console.print(f"[dim]Page {page}/{(total + page_size - 1) // page_size} — use: findings --page=N[/]")


# ─── show ─────────────────────────────────────────────────────────────────────

async def cmd_show(state: "REPLState", args: list[str], console: Console) -> None:
    if not state.require_scan():
        console.print("[yellow]No scan results. Run: scan[/]")
        return
    if not args:
        console.print("[yellow]Usage: show <finding-id|number>[/]")
        return

    f = state.get_finding(args[0])
    if f is None:
        console.print(f"[red]Finding not found:[/] {args[0]}")
        return

    sev_style = _SEV_STYLE.get(f.severity.value, "")

    console.print(Panel(
        f"[{sev_style}]{f.severity.value}[/]  Score: [bold]{f.risk_score:.1f}/10[/]  "
        f"ID: [dim]{f.id}[/]",
        title=f.title,
        border_style="red" if f.severity in (Severity.CRITICAL, Severity.HIGH) else "yellow",
    ))

    console.print(f"[bold]Affected:[/] {f.affected_component}")
    console.print(f"[bold]Abuse Categories:[/] {', '.join(c.value for c in f.abuse_categories) or 'none'}")
    console.print()
    console.print("[bold]Evidence:[/]")
    console.print(Syntax(f.evidence[:1500], "text", theme="monokai", line_numbers=False))
    console.print()
    console.print(f"[bold]Impact:[/] {f.impact}")
    console.print(f"[bold]Remediation:[/] {f.remediation}")

    if f.reproduction_steps:
        console.print()
        console.print("[bold]Reproduction Steps:[/]")
        for step in f.reproduction_steps:
            console.print(f"  [dim]▸[/] {step}")

    if f.ai_analysis:
        console.print()
        console.print("[bold cyan]AI Analysis:[/]")
        _print_ai_analysis(f.ai_analysis, console)

    if f.payload_suggestions:
        console.print()
        console.print(f"[bold cyan]Cached Payloads:[/] {len(f.payload_suggestions)} available (run: payloads {f.id})")

    if f.verified is not None:
        status = "[green]✓ Verified[/]" if f.verified else "[red]✗ Not verified[/]"
        console.print(f"\n[bold]Verification Status:[/] {status}")


# ─── verify ───────────────────────────────────────────────────────────────────

async def cmd_verify(state: "REPLState", args: list[str], console: Console) -> None:
    if not state.require_scan():
        console.print("[yellow]No scan results. Run: scan[/]")
        return
    if not args:
        console.print("[yellow]Usage: verify <finding-id|number>[/]")
        return

    f = state.get_finding(args[0])
    if f is None:
        console.print(f"[red]Finding not found:[/] {args[0]}")
        return

    with console.status(f"[cyan]Verifying {f.id}...[/]"):
        # Re-enumerate server and check if the affected component still exists
        try:
            async with state.mcp_client:
                inv = await state.mcp_client.get_inventory()
        except Exception as e:
            console.print(f"[red]Could not connect to server: {e}[/]")
            return

        # Check component still present
        component = f.affected_component.lower()
        still_present = False

        if "tool:" in component:
            tool_name = component.split("tool:")[-1].strip().strip("'")
            still_present = any(t["name"].lower() == tool_name.lower() for t in inv.tools)
        elif "resource" in component:
            still_present = bool(inv.resources or inv.resource_templates)
        elif "mcp server" in component or "transport" in component:
            still_present = True  # Server is reachable
        elif "prompt" in component:
            still_present = bool(inv.prompts)
        else:
            still_present = True  # Cannot determine — assume present

    f.verified = still_present
    status = "[green]✓ CONFIRMED — finding still present[/]" if still_present else "[yellow]Component no longer detected — may be remediated[/]"
    console.print(f"[bold]Verification:[/] {f.id} — {status}")
    ai_logger.log_event("finding_verified", finding_id=f.id, result=still_present)


# ─── Command registry ─────────────────────────────────────────────────────────

COMMANDS: dict[str, tuple] = {
    "scan":     (cmd_scan,     "Run/re-run security scan"),
    "rescan":   (cmd_scan,     "Alias for scan"),
    "findings": (cmd_findings, "List all findings"),
    "f":        (cmd_findings, "Alias for findings"),
    "show":     (cmd_show,     "Show finding detail"),
    "s":        (cmd_show,     "Alias for show"),
    "verify":   (cmd_verify,   "Verify finding is still present"),
    "v":        (cmd_verify,   "Alias for verify"),
}
