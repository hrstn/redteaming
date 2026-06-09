"""AI analysis and payload generation REPL command handlers: ai, payloads."""
from __future__ import annotations

from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from ._shared import _engine, _print_ai_analysis

if TYPE_CHECKING:
    from ..state import REPLState


# ─── ai ───────────────────────────────────────────────────────────────────────

async def cmd_ai(state: "REPLState", args: list[str], console: Console) -> None:
    if not state.require_scan():
        console.print("[yellow]No scan results. Run: scan[/]")
        return
    if not args:
        console.print("[yellow]Usage: ai <finding-id|number>[/]")
        return
    if state.ai_client is None:
        console.print("[red]AI not configured.[/] Start with --ai-mode and provider flags.")
        return

    fid = args[0]
    if fid.lower() == "surface":
        await _ai_surface_summary(state, console)
        return

    f = state.get_finding(fid)
    if f is None:
        console.print(f"[red]Finding not found:[/] {fid}")
        return

    # Return cached result unless --refresh
    if f.id in state.ai_cache and "--refresh" not in args:
        console.print("[dim]Cached AI result (use --refresh to re-run):[/]")
        _print_ai_analysis(state.ai_cache[f.id], console)
        return

    context = state.scan_result.server_inventory.to_dict() if state.scan_result else None

    with console.status(f"[cyan]Analysing {f.id} with {state.ai_client.mode} AI...[/]"):
        try:
            result = await state.ai_client.analyze_finding(f, context)
        except Exception as e:
            console.print(f"[red]AI error:[/] {e}")
            return

    # Store back into finding and cache
    f.ai_analysis = result
    state.ai_cache[f.id] = result
    _print_ai_analysis(result, console)


async def _ai_surface_summary(state: "REPLState", console: Console) -> None:
    with console.status("[cyan]Generating attack surface summary...[/]"):
        try:
            result = await state.ai_client.attack_surface_summary(state.scan_result)
        except Exception as e:
            console.print(f"[red]AI error:[/] {e}")
            return

    console.print(Panel(
        result.get("executive_summary", "N/A"),
        title="[bold cyan]Executive Summary[/]",
        border_style="cyan",
    ))

    crit = result.get("critical_attack_surfaces", [])
    if crit:
        console.print("\n[bold]Critical Attack Surfaces:[/]")
        for s in crit:
            console.print(f"  [red]▸[/] {s}")

    tbv = result.get("trust_boundary_violations", [])
    if tbv:
        console.print("\n[bold]Trust Boundary Violations:[/]")
        for s in tbv:
            console.print(f"  [dark_orange]▸[/] {s}")

    actions = result.get("recommended_actions", [])
    if actions:
        console.print("\n[bold]Recommended Actions:[/]")
        for i, a in enumerate(actions, 1):
            console.print(f"  {i}. {a}")

    narrative = result.get("risk_narrative", "")
    if narrative:
        console.print("\n[bold]Risk Narrative:[/]")
        console.print(f"  [dim]{narrative}[/]")


# ─── payloads ─────────────────────────────────────────────────────────────────

async def cmd_payloads(state: "REPLState", args: list[str], console: Console) -> None:
    if not state.require_scan():
        console.print("[yellow]No scan results. Run: scan[/]")
        return
    if not args:
        console.print("[yellow]Usage: payloads <finding-id|number>[/]")
        return

    f = state.get_finding(args[0])
    if f is None:
        console.print(f"[red]Finding not found:[/] {args[0]}")
        return

    use_ai = "--ai" in args and state.ai_client is not None

    # Use cache unless --refresh
    if f.id in state.payload_cache and "--refresh" not in args:
        payloads = state.payload_cache[f.id]
        console.print(f"[dim]Cached ({len(payloads)} payloads). Use --refresh to regenerate.[/]")
    elif use_ai:
        with console.status("[cyan]Generating AI-assisted payloads...[/]"):
            try:
                ai_result = await state.ai_client.suggest_payloads(f)
                payloads = ai_result.get("payloads", [])
                if ai_result.get("notes"):
                    console.print(f"[dim]AI notes: {ai_result['notes']}[/]")
            except Exception as e:
                console.print(f"[yellow]AI failed ({e}), falling back to static engine.[/]")
                payloads = _engine.generate_safe_tests(f)
    else:
        payloads = _engine.generate_safe_tests(f)

    # Cache
    state.payload_cache[f.id] = payloads
    f.payload_suggestions = payloads

    t = Table(
        title=f"Safe Validation Payloads for {f.id}",
        box=box.SIMPLE_HEAVY,
        show_lines=True,
        padding=(0, 1),
    )
    t.add_column("#", style="dim", width=3, justify="right")
    t.add_column("Type", width=32)
    t.add_column("Value", width=35)
    t.add_column("Expected Behavior")

    for i, p in enumerate(payloads, 1):
        val = p.get("value")
        val_str = repr(val)[:33] if val is not None else "[dim]null[/]"
        t.add_row(
            str(i),
            f"[cyan]{p.get('type', '?')}[/]",
            val_str,
            p.get("expected_behavior", p.get("description", ""))[:60],
        )

    console.print(t)
    console.print(f"[dim]All {len(payloads)} payloads are safe detection inputs only. "
                  "Use: export payloads/{f.id}.json to save.[/]")


# ─── Command registry ─────────────────────────────────────────────────────────

COMMANDS: dict[str, tuple] = {
    "ai":       (cmd_ai,       "AI analysis of a finding"),
    "payloads": (cmd_payloads, "Generate safe validation payloads"),
    "p":        (cmd_payloads, "Alias for payloads"),
}
