"""Session-management REPL command handlers: history, export, help."""
from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console

from ...reporters import json_reporter, html_reporter, sarif_reporter
from ...ai import logger as ai_logger

if TYPE_CHECKING:
    from ..state import REPLState


# ─── history ──────────────────────────────────────────────────────────────────

async def cmd_history(state: "REPLState", args: list[str], console: Console) -> None:
    if not state.command_history:
        console.print("[dim]No command history yet.[/]")
        return
    for i, cmd in enumerate(state.command_history[-50:], 1):
        console.print(f"  [dim]{i:3}[/]  {cmd}")


# ─── export ───────────────────────────────────────────────────────────────────

async def cmd_export(state: "REPLState", args: list[str], console: Console) -> None:
    if not state.require_scan():
        console.print("[yellow]No scan results. Run: scan[/]")
        return

    # Export session log
    if args and args[0].startswith("log"):
        path = args[1] if len(args) > 1 else "mcpray_session.jsonl"
        ai_logger.export_log(path)
        console.print(f"[green]✓[/] Session log exported: {path}")
        return

    # Export payload cache for a specific finding
    if args and args[0].startswith("payload"):
        fid = args[1] if len(args) > 1 else None
        if fid:
            f = state.get_finding(fid)
            if f and f.payload_suggestions:
                path = f"payloads_{f.id}.json"
                Path(path).write_text(json.dumps(f.payload_suggestions, indent=2))
                console.print(f"[green]✓[/] Payloads exported: {path}")
                return
        console.print("[yellow]Usage: export payloads <finding-id>[/]")
        return

    # Full scan result export
    stem = args[0] if args else "mcpray_interactive_export"
    stem = stem.replace(".json", "").replace(".html", "")
    json_reporter.write(state.scan_result, f"{stem}.json")
    html_reporter.write(state.scan_result, f"{stem}.html")
    sarif_reporter.write(state.scan_result, f"{stem}.sarif")
    console.print(f"[green]✓[/] Exported: {stem}.json, {stem}.html, {stem}.sarif")
    ai_logger.log_event("export", files=[f"{stem}.json", f"{stem}.html", f"{stem}.sarif"])


# ─── help ─────────────────────────────────────────────────────────────────────

HELP_TEXT = """\
[bold cyan]mcpray REPL Commands[/]

[bold]Discovery[/]
  [cyan]discover[/] <target>                           Scan host/CIDR for MCP servers
  [cyan]discover[/] <target> --ports 8000-9000         Custom port range
  [cyan]discover[/] <target> --no-enum                 Skip capability enum (faster)
  [cyan]discover[/] <target> --https-only

[bold]Scanning[/]
  [cyan]scan[/] [--active] [--deep]    Run/re-run security scan
  [cyan]findings[/] [--page=N]         List all findings
  [cyan]show[/] <id|#>                 Show finding details
  [cyan]verify[/] <id|#>               Re-check if finding still present

[bold]SQL Injection[/]
  [cyan]sqli[/]                                        Auto-detect injectable templates
  [cyan]sqli[/] --template <tpl> --param <p>          Target specific template
  [cyan]sqli[/] --template <tpl> --param <p> --dump-tables
  [cyan]sqli[/] --template <tpl> --param <p> --dump-all
  [cyan]sqli[/] --template <tpl> --param <p> --sqlmap-export

[bold]Exploitation[/]
  [cyan]cmdinj[/] --tool <name> --param <name>         CMDi exploiter (whoami, revshells, file dump)
  [cyan]cmdinj[/] --tool <name> --param <name> --lhost IP --lport PORT
  [cyan]ssrf[/] --tool <name> --param <name>           SSRF exploiter (cloud metadata, internal ports)
  [cyan]credharvest[/] --template <tpl> --param <p>    Post-SQLi credential dumper

[bold]Protocol Analysis[/]
  [cyan]fuzz[/] [--max-cases N]                        Protocol fuzzer (malformed JSON-RPC)
  [cyan]graph[/] [--output FILE]                       Attack graph (tool dependency + exploitation chains)
  [cyan]taint[/]                                       Data flow taint analysis (static, no requests)
  [cyan]mitm[/] [--port P] [--output FILE]             Start MITM proxy, press Enter to stop

[bold]MCP-Specific Checks[/]
  [cyan]pi[/]                                          Indirect prompt injection scanner
  [cyan]shadow[/]                                      Tool shadowing / impersonation detector
  [cyan]poison[/]                                      Context window poisoning scanner

[bold]Output[/]
  [cyan]nuclei[/] [--output-dir DIR] [--min-severity S]  Generate Nuclei YAML templates
  [cyan]poc[/] [--output-dir DIR] [--min-severity S]      Generate runnable Python PoC scripts

[bold]AI Analysis[/]  [dim](requires --ai-mode flag at startup)[/]
  [cyan]ai[/] <id|#>                   Analyse finding with AI
  [cyan]ai surface[/]                  Full attack surface summary
  [cyan]ai[/] <id|#> --refresh         Force re-analysis

[bold]Payload Generation[/]
  [cyan]payloads[/] <id|#>             Generate safe validation payloads
  [cyan]payloads[/] <id|#> --ai        AI-assisted payload generation
  [cyan]payloads[/] <id|#> --refresh   Regenerate payloads

[bold]Server Exploration[/]
  [cyan]tools[/]                          List all MCP tools
  [cyan]resources[/]                      List resources + templates with index
  [cyan]resources get[/] <name|#>         Fetch and view resource content
  [cyan]resources get[/] <name|#> [dim]--page=N[/]  Page through large content
  [cyan]resources save[/] <name|#> [file] Download resource content to a file
  [cyan]resources scan[/] <name|#>        Scan resource content for secrets/credentials
  [cyan]resources all[/]                  Fetch all resources and show secret summary
  [cyan]prompts[/]                        List prompts
  [cyan]call[/] <tool-name>               Preview/execute a tool [dim](dry-run default)[/]

[bold]Session[/]
  [cyan]history[/]                      Command history
  [cyan]export[/] [stem]               Export findings (JSON/HTML/SARIF)
  [cyan]export log[/] [file]           Export session audit log
  [cyan]export payloads[/] <id>        Export payload suggestions
  [cyan]exit[/] / [cyan]quit[/] / [cyan]q[/]               Exit REPL
"""


async def cmd_help(state: "REPLState", args: list[str], console: Console) -> None:
    console.print(HELP_TEXT)


# ─── Command registry ─────────────────────────────────────────────────────────

COMMANDS: dict[str, tuple] = {
    "history": (cmd_history, "Show command history"),
    "h":       (cmd_history, "Alias for history"),
    "export":  (cmd_export,  "Export results"),
    "help":    (cmd_help,    "Show this help"),
    "?":       (cmd_help,    "Alias for help"),
}
