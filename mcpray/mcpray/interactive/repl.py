"""Main REPL loop for mcpray interactive mode."""
from __future__ import annotations

import asyncio
import shlex
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

from ..ai import logger as ai_logger
from ..ai.client import AIClient, AIMode
from ..client import MCPClient
from .commands import COMMANDS
from .state import REPLState

_HISTORY_FILE = Path.home() / ".mcpray_history"

# ── prompt_toolkit autocomplete tree ─────────────────────────────────────────
# None = leaf node (no sub-completions). Dict = nested completions.

_CMD_COMPLETIONS: dict = {
    # Scanning
    "scan":         {"--active": None, "--deep": None},
    "rescan":       {"--active": None, "--deep": None},
    "findings":     {"--page=": None},
    "f":            None,
    "show":         None,
    "s":            None,
    "verify":       None,
    "v":            None,
    # AI
    "ai":           {"surface": None, "--refresh": None},
    "payloads":     {"--ai": None, "--refresh": None},
    "p":            None,
    # Server exploration
    "call":         None,
    "tools":        None,
    "t":            None,
    "resources":    {"get": None, "save": None, "scan": None, "all": None},
    "r":            None,
    "prompts":      None,
    # Discovery
    "discover": {
        "--ports": None, "--no-enum": None,
        "--https-only": None, "--http-only": None,
    },
    # SQL injection
    "sqli": {
        "--template": None, "--param": None,
        "--dump-tables": None, "--dump-all": None,
        "--sqlmap-export": None, "--proxy-port": None,
    },
    # Exploitation
    "cmdinj": {
        "--tool": None, "--param": None, "--base-value": None,
        "--lhost": None, "--lport": None, "--no-enum": None,
    },
    "ssrf": {
        "--tool": None, "--param": None,
        "--no-cloud": None, "--no-internal": None,
    },
    "credharvest": {
        "--template": None, "--param": None, "--extra-tables": None,
    },
    # Protocol analysis
    "fuzz":     {"--max-cases": None},
    "graph":    {"--output": None},
    "taint":    None,
    "mitm":     {"--port": None, "--output": None},
    # MCP-specific
    "pi":       None,
    "shadow":   None,
    "poison":   None,
    # Output
    "nuclei":   {"--output-dir": None, "--min-severity": None},
    "poc":      {"--output-dir": None, "--min-severity": None},
    # Session
    "history":  None,
    "h":        None,
    "export":   {"log": None, "payloads": None},
    # Meta
    "help":     None,
    "?":        None,
    "exit":     None,
    "quit":     None,
    "q":        None,
}

# ── prompt_toolkit setup (optional) ──────────────────────────────────────────

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.completion import NestedCompleter
    from prompt_toolkit.history import FileHistory
    from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
    from prompt_toolkit.styles import Style

    _HAS_PT = True

    _PT_STYLE = Style.from_dict({
        "prompt":                          "bold ansicyan",
        "completion-menu.completion":      "bg:#1a1a2e #e0e0e0",
        "completion-menu.completion.current": "bg:#0066cc #ffffff bold",
        "completion-menu.meta.completion": "bg:#1a1a2e #888888",
        "scrollbar.background":            "bg:#222222",
        "scrollbar.button":                "bg:#888888",
        "auto-suggestion":                 "#555555 italic",
    })

except ImportError:
    _HAS_PT = False


def _make_pt_session() -> "PromptSession | None":
    """Return a prompt_toolkit PromptSession with full autocomplete, or None."""
    if not _HAS_PT:
        return None
    try:
        completer = NestedCompleter.from_nested_dict(_CMD_COMPLETIONS)
        return PromptSession(
            history=FileHistory(str(_HISTORY_FILE)),
            completer=completer,
            auto_suggest=AutoSuggestFromHistory(),
            style=_PT_STYLE,
            complete_while_typing=True,
            mouse_support=False,
            reserve_space_for_menu=4,
        )
    except Exception:
        return None


# ── readline fallback ─────────────────────────────────────────────────────────

def _setup_readline(completions: list[str]) -> None:
    try:
        import readline
        try:
            readline.read_history_file(_HISTORY_FILE)
        except (FileNotFoundError, PermissionError, OSError):
            pass

        import atexit

        def _safe_write() -> None:
            try:
                readline.write_history_file(_HISTORY_FILE)
            except (PermissionError, OSError):
                pass

        atexit.register(_safe_write)

        def _completer(text: str, state: int) -> str | None:
            opts = [c for c in completions if c.startswith(text)]
            return opts[state] if state < len(opts) else None

        readline.set_completer(_completer)
        readline.parse_and_bind("tab: complete")
    except ImportError:
        pass


async def _ainput_plain(prompt_text: str) -> str:
    """Fallback input — runs in executor so the event loop stays alive."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, input, prompt_text)


# ── Main REPL ─────────────────────────────────────────────────────────────────

async def run_interactive(
    target: str,
    ai_mode: AIMode | None = None,
    openai_api_key: str | None = None,
    openai_base_url: str = "https://api.openai.com/v1",
    openai_model: str = "gpt-4o-mini",
    ollama_base_url: str = "http://localhost:11434",
    ollama_model: str = "llama3.2",
    load_file: str | None = None,
    unsafe_mode: bool = False,
    headers: dict | None = None,
    timeout: int = 30,
    log_dir: str = ".",
) -> None:
    console = Console()

    log_path = ai_logger.init_session(log_dir)

    ai_client: AIClient | None = None
    if ai_mode:
        ai_client = AIClient(
            mode=ai_mode,
            openai_api_key=openai_api_key,
            openai_base_url=openai_base_url,
            openai_model=openai_model,
            ollama_base_url=ollama_base_url,
            ollama_model=ollama_model,
        )
        with console.status("[dim]Checking AI provider connectivity...[/]"):
            health = await ai_client.health_check()
        for provider, ok in health.items():
            icon = "[green]✓[/]" if ok else "[red]✗[/]"
            console.print(f"  {icon} {provider}")

    mcp_client = MCPClient(target, headers=headers or {}, timeout=timeout)
    state = REPLState(
        target=target,
        mcp_client=mcp_client,
        ai_client=ai_client,
        unsafe_mode=unsafe_mode,
    )

    if load_file:
        try:
            from ..cli import _reconstruct_result
            import json
            data = json.loads(Path(load_file).read_text())
            state.scan_result = _reconstruct_result(data)
            console.print(f"[green]✓[/] Loaded: {load_file} — {len(state.scan_result.findings)} findings")
        except Exception as e:
            console.print(f"[yellow]Could not load {load_file}: {e}[/]")

    # Set up input — prompt_toolkit if available, readline otherwise
    pt_session = _make_pt_session()
    if pt_session is None:
        _setup_readline(list(COMMANDS.keys()))
        completion_info = "[dim]tab-complete[/]: readline (install prompt_toolkit for inline autocomplete)"
    else:
        completion_info = "[dim]tab-complete[/]: inline autocomplete + ghost text active"

    ai_info = f" · AI: {ai_mode}" if ai_mode else " · AI: disabled"
    unsafe_info = " · [bold red]UNSAFE MODE[/]" if unsafe_mode else ""
    console.print(Panel(
        f"[bold]Target:[/] {target}\n"
        f"[bold]Transport:[/] {mcp_client.transport}{ai_info}{unsafe_info}\n"
        f"[dim]Session log:[/] {log_path}\n"
        f"{completion_info}\n"
        f"Type [bold cyan]help[/] for commands. [bold cyan]scan[/] to begin.",
        title="[bold cyan]mcpray interactive v1.0.0[/]",
        border_style="cyan",
    ))

    if state.scan_result is None:
        console.print("[dim]No scan loaded — run [bold cyan]scan[/] to start.[/]\n")

    # ── Main loop ──────────────────────────────────────────────────────────
    while True:
        try:
            if pt_session is not None:
                # prompt_toolkit: async prompt with live autocomplete dropdown
                raw = await pt_session.prompt_async("mcpray › ")
            else:
                raw = await _ainput_plain("mcpray › ")
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Exiting.[/]")
            break

        line = raw.strip()
        if not line:
            continue

        ai_logger.log_repl_command(line)
        state.record_command(line)

        try:
            parts = shlex.split(line)
        except ValueError:
            parts = line.split()
        cmd_name = parts[0].lower()
        cmd_args = parts[1:]

        if cmd_name in ("exit", "quit", "q"):
            console.print("[dim]Goodbye.[/]")
            break

        if cmd_name not in COMMANDS:
            console.print(f"[red]Unknown command:[/] {cmd_name!r}  (type [cyan]help[/])")
            continue

        handler, _ = COMMANDS[cmd_name]
        try:
            await handler(state, cmd_args, console)
        except KeyboardInterrupt:
            console.print("\n[dim]Interrupted.[/]")
        except Exception as e:
            console.print(f"[red]Error in {cmd_name}:[/] {e}")
            if "--debug" in sys.argv:
                console.print_exception()
