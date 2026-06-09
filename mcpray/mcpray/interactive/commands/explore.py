"""Server exploration REPL command handlers: call, tools, resources, prompts."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich import box

from ...ai import logger as ai_logger

from ._shared import _ainput

if TYPE_CHECKING:
    from ..state import REPLState


# ─── call ─────────────────────────────────────────────────────────────────────

async def cmd_call(state: "REPLState", args: list[str], console: Console) -> None:
    if not state.require_scan():
        console.print("[yellow]No scan results. Run: scan[/]")
        return
    if not args:
        console.print("[yellow]Usage: call <tool-name>[/]")
        return

    tool_name = args[0]
    tool = state.get_tool(tool_name)
    if tool is None:
        console.print(f"[red]Tool not found:[/] {tool_name}")
        tools = [t["name"] for t in state.scan_result.server_inventory.tools]
        if tools:
            console.print(f"[dim]Available: {', '.join(tools)}[/]")
        return

    schema = tool.get("inputSchema", {}) or {}
    properties = schema.get("properties", {}) or {}
    required = schema.get("required", []) or []

    console.print(Panel(
        f"[bold]{tool_name}[/]\n{tool.get('description', '')[:200]}",
        title="[bold]Tool: Dry Run Mode[/]",
        border_style="yellow",
    ))

    # Collect parameter values
    call_args: dict = {}
    for param, pdef in properties.items():
        p_type = pdef.get("type", "string")
        p_desc = pdef.get("description", "")[:60]
        req_marker = " [red][required][/]" if param in required else ""
        prompt_str = f"  {param} ({p_type}){req_marker} — {p_desc}\n  > "
        val_str = (await _ainput(prompt_str)).strip()
        if val_str:
            if p_type == "integer":
                try:
                    call_args[param] = int(val_str)
                except ValueError:
                    call_args[param] = val_str
            elif p_type == "number":
                try:
                    call_args[param] = float(val_str)
                except ValueError:
                    call_args[param] = val_str
            elif p_type == "boolean":
                call_args[param] = val_str.lower() in ("true", "yes", "1", "y")
            else:
                call_args[param] = val_str

    # Show preview
    console.print()
    console.print(Syntax(
        f"await client.call_tool('{tool_name}', {json.dumps(call_args, indent=2)})",
        "python", theme="monokai",
    ))
    console.print()

    if not state.unsafe_mode:
        console.print("[yellow]DRY RUN MODE — tool not executed (start with --unsafe-mode to enable execution)[/]")
        ai_logger.log_tool_call(tool_name, call_args, dry_run=True, confirmed=False)
        return

    confirm = await _ainput("[bold red]UNSAFE MODE: Execute this tool call? [y/N]: [/]")
    if confirm.strip().lower() != "y":
        console.print("[dim]Cancelled.[/]")
        ai_logger.log_tool_call(tool_name, call_args, dry_run=False, confirmed=False)
        return

    ai_logger.log_tool_call(tool_name, call_args, dry_run=False, confirmed=True)
    with console.status(f"[cyan]Calling {tool_name}...[/]"):
        async with state.mcp_client:
            result = await state.mcp_client.call_tool(tool_name, call_args)

    state.tool_call_log.append({
        "tool": tool_name,
        "args": call_args,
        "result": result,
        "ts": datetime.now(timezone.utc).isoformat(),
    })

    if result.get("is_error"):
        console.print(f"[red]Tool returned error:[/] {result.get('error', '')}")
    else:
        content = "\n".join(result.get("content", []))
        console.print(Panel(content[:2000] or "[dim](empty response)[/]", title="Tool Result", border_style="green"))


# ─── tools / resources / prompts ─────────────────────────────────────────────

async def cmd_tools(state: "REPLState", args: list[str], console: Console) -> None:
    if not state.require_scan():
        console.print("[yellow]Run: scan[/]")
        return
    inv = state.scan_result.server_inventory
    t = Table(title=f"Tools ({len(inv.tools)})", box=box.SIMPLE_HEAVY, padding=(0, 1))
    t.add_column("Name", style="bold cyan")
    t.add_column("Parameters")
    t.add_column("Description")
    for tool in inv.tools:
        params = ", ".join(tool.get("inputSchema", {}).get("properties", {}).keys())
        t.add_row(tool["name"], params[:40] or "—", tool.get("description", "")[:60])
    console.print(t)


# ─── resources (enhanced) ────────────────────────────────────────────────────

_PAGE_SIZE = 80        # lines per page when paging
_MAX_SCAN_BYTES = 256_000  # content size cap for secret scanning

_MIME_TO_LEXER: dict[str, str] = {
    "application/json": "json",
    "text/json": "json",
    "text/html": "html",
    "text/xml": "xml",
    "application/xml": "xml",
    "text/yaml": "yaml",
    "application/yaml": "yaml",
    "text/x-python": "python",
    "text/python": "python",
    "text/markdown": "markdown",
    "text/csv": "text",
    "text/plain": "text",
}


def _lexer_for(mime: str, content: str) -> str:
    if mime:
        for k, v in _MIME_TO_LEXER.items():
            if k in mime.lower():
                return v
    stripped = content.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            json.loads(content)
            return "json"
        except Exception:
            pass
    if any(stripped.startswith(t) for t in ("<?xml", "<html", "<!DOCTYPE", "<svg")):
        return "html"
    if stripped.startswith("---\n") or (": " in content[:200] and "\n" in content[:200]):
        return "yaml"
    return "text"


def _is_binary(content: str) -> bool:
    if not content:
        return False
    sample = content[:512]
    non_printable = sum(1 for c in sample if ord(c) < 9 or (13 < ord(c) < 32))
    return non_printable / len(sample) > 0.10


def _find_resource(inv, selector: str) -> tuple[dict | None, bool]:
    """Lookup resource by 1-based index, exact name, or URI substring.
    Returns (resource_dict, is_template).
    """
    all_items = [(r, False) for r in inv.resources] + \
                [(t, True) for t in inv.resource_templates]
    try:
        idx = int(selector) - 1
        if 0 <= idx < len(all_items):
            return all_items[idx]
    except ValueError:
        pass
    sel = selector.lower()
    for item, is_tmpl in all_items:
        name = item.get("name", "").lower()
        uri = item.get("uri", item.get("uriTemplate", "")).lower()
        if sel == name or sel == uri or sel in name or sel in uri:
            return item, is_tmpl
    return None, False


async def _resolve_uri(resource: dict, is_template: bool, console: Console) -> str | None:
    """Return the concrete URI to read. Prompts for template parameters."""
    import re
    if not is_template:
        return resource.get("uri", "")
    template = resource.get("uriTemplate", "")
    # Match any {…} block — handles RFC 6570 operators like {file_name*}, {+path}
    blocks = re.findall(r"\{([^}]+)\}", template)
    if not blocks:
        return template
    console.print(f"  [dim]Template:[/] {template}")
    filled = template
    for block in blocks:
        # Strip RFC 6570 level-2 operators (+, #, /, ., ;, ?, &) and explode modifier (*)
        clean = re.sub(r'^[+#./;?&]', '', block).rstrip('*,')
        val = (await _ainput(f"  {clean}: ")).strip()
        if not val:
            console.print(f"[yellow]No value for '{clean}' — cancelled.[/]")
            return None
        filled = filled.replace("{" + block + "}", val)
    return filled


def _scan_secrets(content: str) -> list[tuple[str, str]]:
    """Run secret-detection patterns over content. Returns (pattern_label, snippet) pairs."""
    import re
    hits: list[tuple[str, str]] = []

    try:
        from ...rules.loader import load_rules, get_content_secret_patterns
        rules = load_rules()
        for pat in get_content_secret_patterns(rules):
            for m in pat.finditer(content[:_MAX_SCAN_BYTES]):
                snippet = m.group(0)[:80]
                label = pat.pattern[:50]
                if (label, snippet) not in hits:
                    hits.append((label, snippet))
    except Exception:
        pass

    extra = [
        (r"(?i)password\s*[:=]\s*['\"]?(\S{6,})", "password assignment"),
        (r"sk-[A-Za-z0-9]{32,}", "OpenAI API key"),
        (r"AKIA[A-Z0-9]{16}", "AWS Access Key ID"),
        (r"ghp_[A-Za-z0-9]{36}", "GitHub PAT"),
        (r"-----BEGIN .{0,30}PRIVATE KEY-----", "private key block"),
        (r"(?i)bearer\s+[A-Za-z0-9._\-]{20,}", "Bearer token"),
        (r"(?i)api[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9+/]{16,}", "API key assignment"),
        (r"[a-zA-Z0-9+/]{40,}={0,2}", "possible base64 secret (long)"),
    ]
    for pat_str, label in extra:
        try:
            for m in re.finditer(pat_str, content[:_MAX_SCAN_BYTES]):
                snippet = m.group(0)[:80]
                if (label, snippet) not in hits:
                    hits.append((label, snippet))
        except re.error:
            pass

    return hits[:30]


async def _display_content(
    content: str, mime: str, uri: str, console: Console, page: int = 1
) -> None:
    if not content:
        console.print("[dim](empty response)[/]")
        return
    if _is_binary(content):
        console.print("[yellow]⚠ Binary content — showing hex preview[/]")
        hex_preview = " ".join(f"{ord(c):02x}" for c in content[:128])
        console.print(Syntax(hex_preview, "text", theme="monokai"))
        return

    lines = content.splitlines()
    total = len(lines)
    start = (page - 1) * _PAGE_SIZE
    end = min(start + _PAGE_SIZE, total)
    chunk = "\n".join(lines[start:end])
    lexer = _lexer_for(mime, content)

    page_info = f"  [yellow]lines {start+1}–{end} of {total}[/]" if total > _PAGE_SIZE else ""
    title = f"[bold]{uri}[/]  [dim]{len(content)} B · {total} lines · {lexer}[/]{page_info}"

    console.print(Panel(
        Syntax(chunk, lexer, theme="monokai", line_numbers=True, start_line=start + 1),
        title=title,
        border_style="blue",
        padding=(0, 1),
    ))

    if end < total:
        remaining = total - end
        console.print(
            f"[dim]  {remaining} more lines — "
            f"use: resources get <name> --page={page + 1}[/]"
        )


# ─── subcommand handlers ──────────────────────────────────────────────────────

def _list_resources(state: "REPLState", console: Console) -> None:
    inv = state.scan_result.server_inventory
    total = len(inv.resources) + len(inv.resource_templates)
    t = Table(
        title=f"Resources  ({len(inv.resources)} concrete · {len(inv.resource_templates)} templates)",
        box=box.SIMPLE_HEAVY, padding=(0, 1), show_lines=False,
    )
    t.add_column("#", style="dim", width=3, justify="right")
    t.add_column("Name", style="bold cyan", width=24)
    t.add_column("URI / Template")
    t.add_column("MIME", width=20)
    t.add_column("Description")

    idx = 1
    for r in inv.resources:
        t.add_row(
            str(idx), r.get("name", ""), r.get("uri", "")[:55],
            r.get("mimeType", "")[:18], r.get("description", "")[:55],
        )
        idx += 1
    if inv.resource_templates:
        t.add_row("", "[dim]── templates ──[/]", "", "", "")
        for r in inv.resource_templates:
            t.add_row(
                str(idx), r.get("name", ""), r.get("uriTemplate", "")[:55],
                r.get("mimeType", "")[:18], r.get("description", "")[:55],
            )
            idx += 1

    console.print(t)
    console.print(
        "[dim]  get <name|#>  ·  save <name|#> [file]  ·  "
        "scan <name|#>  ·  all[/]"
    )


async def _resource_get(
    state: "REPLState", args: list[str], console: Console
) -> None:
    if not args:
        console.print("[yellow]Usage: resources get <name|#|uri> [--page=N][/]")
        return

    page = 1
    selector = args[0]
    for a in args[1:]:
        if a.startswith("--page="):
            try:
                page = int(a.split("=")[1])
            except ValueError:
                pass

    inv = state.scan_result.server_inventory
    resource, is_tmpl = _find_resource(inv, selector)
    if resource is None:
        console.print(f"[red]Resource not found:[/] {selector}")
        return

    uri = await _resolve_uri(resource, is_tmpl, console)
    if uri is None:
        return

    mime = resource.get("mimeType", "")
    with console.status(f"[cyan]Fetching {uri}...[/]"):
        async with state.mcp_client:
            content = await state.mcp_client.read_resource(uri)

    if content is None:
        console.print(f"[red]No content returned for:[/] {uri}")
        return

    await _display_content(content, mime, uri, console, page)
    ai_logger.log_event("resource_fetched", uri=uri, size=len(content), mime=mime)


async def _resource_save(
    state: "REPLState", args: list[str], console: Console
) -> None:
    if not args:
        console.print("[yellow]Usage: resources save <name|#> [filename][/]")
        return

    inv = state.scan_result.server_inventory
    resource, is_tmpl = _find_resource(inv, args[0])
    if resource is None:
        console.print(f"[red]Resource not found:[/] {args[0]}")
        return

    uri = await _resolve_uri(resource, is_tmpl, console)
    if uri is None:
        return

    # Derive default filename
    default_name = (
        args[1] if len(args) > 1
        else uri.split("/")[-1].split("?")[0] or "resource.txt"
    )
    if "." not in default_name:
        ext = {"json": ".json", "html": ".html", "yaml": ".yaml", "xml": ".xml"}.get(
            _lexer_for(resource.get("mimeType", ""), ""), ".txt"
        )
        default_name += ext

    with console.status(f"[cyan]Fetching {uri}...[/]"):
        async with state.mcp_client:
            content = await state.mcp_client.read_resource(uri)

    if content is None:
        console.print(f"[red]No content returned for:[/] {uri}")
        return

    Path(default_name).write_text(content, encoding="utf-8", errors="replace")
    console.print(f"[green]✓[/] Saved {len(content)} bytes → [bold]{default_name}[/]")
    ai_logger.log_event("resource_saved", uri=uri, file=default_name, size=len(content))


async def _resource_scan(
    state: "REPLState", args: list[str], console: Console
) -> None:
    if not args:
        console.print("[yellow]Usage: resources scan <name|#>[/]")
        return

    inv = state.scan_result.server_inventory
    resource, is_tmpl = _find_resource(inv, args[0])
    if resource is None:
        console.print(f"[red]Resource not found:[/] {args[0]}")
        return

    uri = await _resolve_uri(resource, is_tmpl, console)
    if uri is None:
        return

    with console.status(f"[cyan]Fetching and scanning {uri}...[/]"):
        async with state.mcp_client:
            content = await state.mcp_client.read_resource(uri)

    if content is None:
        console.print(f"[red]No content returned for:[/] {uri}")
        return

    console.print(f"[dim]Scanned {len(content)} bytes from {uri}[/]")
    hits = _scan_secrets(content)

    if not hits:
        console.print("[green]✓ No secret patterns detected in resource content.[/]")
        return

    console.print(f"[bold red]⚠ {len(hits)} potential secret(s) found:[/]")
    t = Table(box=box.SIMPLE_HEAVY, padding=(0, 1), show_lines=True)
    t.add_column("#", style="dim", width=3, justify="right")
    t.add_column("Pattern", style="yellow", width=35)
    t.add_column("Matched Value")

    for i, (label, snippet) in enumerate(hits, 1):
        # Partially redact the matched value for display safety
        redacted = snippet[:12] + "…" + snippet[-4:] if len(snippet) > 20 else snippet
        t.add_row(str(i), label[:33], f"[bold red]{redacted}[/]")

    console.print(t)
    console.print(
        "[dim]Use: resources save <name> to dump full content for manual review.[/]"
    )
    ai_logger.log_event("resource_secret_scan", uri=uri, hits=len(hits))


async def _resource_all(state: "REPLState", console: Console) -> None:
    """Fetch every concrete resource and display a summary table."""
    inv = state.scan_result.server_inventory
    if not inv.resources:
        console.print("[dim]No concrete resources to fetch.[/]")
        return

    results: list[tuple[str, str, int, list]] = []  # name, uri, size, hits

    for r in inv.resources:
        uri = r.get("uri", "")
        name = r.get("name", "")
        with console.status(f"[cyan]  Fetching {name or uri}...[/]"):
            try:
                async with state.mcp_client:
                    content = await state.mcp_client.read_resource(uri)
            except Exception as e:
                content = None
                console.print(f"  [red]✗ {name}: {e}[/]")
                continue

        if content is None:
            console.print(f"  [yellow]✗ {name}: empty[/]")
            results.append((name, uri, 0, []))
            continue

        hits = _scan_secrets(content)
        results.append((name, uri, len(content), hits))
        secret_flag = f"[bold red]{len(hits)} secrets![/]" if hits else "[green]clean[/]"
        console.print(f"  [green]✓[/] {name}  [dim]{len(content)} B[/]  {secret_flag}")

    # Summary table
    console.print()
    t = Table(title="Resource Fetch Summary", box=box.ROUNDED, padding=(0, 1))
    t.add_column("Name", style="bold cyan")
    t.add_column("URI")
    t.add_column("Size", justify="right")
    t.add_column("Secrets Found", justify="center")
    for name, uri, size, hits in results:
        sec_cell = (
            f"[bold red]{len(hits)}[/]" if hits else "[green]0[/]"
        )
        t.add_row(name, uri[:45], f"{size:,} B", sec_cell)
    console.print(t)
    ai_logger.log_event("resource_all_fetched", count=len(results))


# ─── cmd_resources dispatcher ─────────────────────────────────────────────────

async def cmd_resources(state: "REPLState", args: list[str], console: Console) -> None:
    if not state.require_scan():
        console.print("[yellow]Run: scan[/]")
        return

    if not args:
        _list_resources(state, console)
        return

    sub = args[0].lower()
    rest = args[1:]

    if sub == "get":
        await _resource_get(state, rest, console)
    elif sub == "save":
        await _resource_save(state, rest, console)
    elif sub == "scan":
        await _resource_scan(state, rest, console)
    elif sub == "all":
        await _resource_all(state, console)
    else:
        # Bare name/index/URI → shorthand for 'get'
        await _resource_get(state, args, console)


async def cmd_prompts(state: "REPLState", args: list[str], console: Console) -> None:
    if not state.require_scan():
        console.print("[yellow]Run: scan[/]")
        return
    inv = state.scan_result.server_inventory
    if not inv.prompts:
        console.print("[dim]No prompts exposed by this server.[/]")
        return
    t = Table(title=f"Prompts ({len(inv.prompts)})", box=box.SIMPLE_HEAVY, padding=(0, 1))
    t.add_column("Name", style="bold cyan")
    t.add_column("Arguments")
    t.add_column("Description")
    for p in inv.prompts:
        arg_names = ", ".join(a.get("name", "") for a in p.get("arguments", []))
        t.add_row(p["name"], arg_names or "—", p.get("description", "")[:60])
    console.print(t)


# ─── Command registry ─────────────────────────────────────────────────────────

COMMANDS: dict[str, tuple] = {
    "call":      (cmd_call,      "Preview/execute MCP tool call"),
    "tools":     (cmd_tools,     "List MCP tools"),
    "t":         (cmd_tools,     "Alias for tools"),
    "resources": (cmd_resources, "List MCP resources"),
    "r":         (cmd_resources, "Alias for resources"),
    "prompts":   (cmd_prompts,   "List MCP prompts"),
}
