"""Nuclei template generator — converts mcpray findings into Nuclei YAML templates."""
from __future__ import annotations

import json
import re
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

from ..findings import Finding, ScanResult, Severity

try:  # PyYAML is optional — fall back to manual string building if absent.
    import yaml  # type: ignore

    _HAVE_YAML = True
except Exception:  # pragma: no cover - import guard
    yaml = None  # type: ignore
    _HAVE_YAML = False


# ── Severity / id mapping ────────────────────────────────────────────────────

_SEVERITY_MAP = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.INFORMATIONAL: "info",
}


def _severity_to_nuclei(severity: Severity) -> str:
    """Map a Severity enum to a Nuclei severity string (info/low/medium/high/critical)."""
    return _SEVERITY_MAP.get(severity, "info")


def _slugify(text: str) -> str:
    """Lower-case kebab-case slug, stripped of unsafe characters."""
    text = text.lower()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    return text.strip("-")


def _finding_to_template_id(finding: Finding) -> str:
    """Generate a safe, kebab-case template ID like ``mcpray-sqli-price-item``."""
    # Prefer a short tag-driven hint, then fall back to the title.
    hint_tags = [t for t in finding.tags if t not in ("confirmed", "active-testing")]
    hint = hint_tags[0] if hint_tags else finding.title
    component = ""
    # Pull a recognisable component name (resource scheme / tool name) out of
    # the affected_component string so similar findings get distinct ids.
    m = re.search(r"([a-z0-9_]+)://\{?([a-z0-9_]+)", finding.affected_component, re.I)
    if m:
        component = f"{m.group(1)}-{m.group(2)}"
    else:
        m = re.search(r"Tool:\s*([a-zA-Z0-9_]+)", finding.affected_component)
        if m:
            component = m.group(1)
    base = "-".join(part for part in (_slugify(hint), _slugify(component)) if part)
    slug = _slugify(f"mcpray-{base}") or f"mcpray-{_slugify(finding.id)}"
    return slug


# ── Payload / matcher extraction ─────────────────────────────────────────────

def _extract_uri_payload(finding: Finding) -> str | None:
    """Pull the read_resource URI used in the PoC out of the reproduction steps."""
    blob = "\n".join(finding.reproduction_steps) + "\n" + finding.evidence
    m = re.search(r'"uri"\s*:\s*"([^"]+)"', blob)
    if m:
        return m.group(1)
    # read_resource('uri') style
    m = re.search(r"read_resource\(\s*['\"]([^'\"]+)['\"]", blob)
    if m:
        return m.group(1)
    return None


def _extract_tool_call(finding: Finding) -> tuple[str, dict] | None:
    """Pull a (tool_name, arguments) pair from the reproduction steps."""
    blob = "\n".join(finding.reproduction_steps)
    m = re.search(r"call_tool\(\s*['\"]([^'\"]+)['\"]\s*,\s*(\{.*\})\s*\)", blob)
    if not m:
        return None
    tool = m.group(1)
    raw = m.group(2)
    # The steps use Python dict literals with single quotes — coerce to JSON.
    try:
        args = json.loads(raw.replace("'", '"'))
    except Exception:
        args = {}
    return tool, args


def _matcher_words(finding: Finding) -> tuple[list[str], str]:
    """Return (words, condition) to confirm the vuln from the response body."""
    tags = set(finding.tags)

    # SQLi — look for the mcpray UNION marker or a SQL error string.
    if "sql-injection" in tags or "sqli" in tags:
        if "union-based" in tags:
            return ["MCPRAY_SQ_MARKER_7z9x"], "or"
        return ["syntax error", "SQLiteException", "PSQLException",
                "You have an error in your SQL", "Unclosed quotation"], "or"

    # Command injection — the echoed marker proves execution.
    if "command-injection" in tags or "rce" in tags or "cmdi" in tags:
        return ["MCPRAY_CMDI_7z9x", "uid=", "root:x:0:0"], "or"

    # SSRF — internal metadata content.
    if "ssrf" in tags:
        if "cloud-metadata" in tags:
            return ["ami-id", "iam/security-credentials", "instance-id",
                    "computeMetadata", "169.254.169.254"], "or"
        return ["169.254.169.254", "localhost", "127.0.0.1"], "or"

    # Prompt injection / context poisoning — surface the injected directive.
    if "prompt-injection" in tags or "context-poison" in tags:
        return ["ignore previous instructions", "SYSTEM:", "<!--", "</instructions>"], "or"

    # Path traversal.
    if "path-traversal" in tags:
        return ["root:x:0:0", "[extensions]", "/etc/passwd"], "or"

    # Generic — derive a stable token from the evidence Response: block.
    m = re.search(r"Response:\s*(.+)", finding.evidence, re.S)
    snippet = (m.group(1) if m else finding.evidence).strip()
    token = ""
    for line in snippet.splitlines():
        line = line.strip().strip('",')
        if len(line) >= 6 and re.search(r"[A-Za-z]", line):
            token = line[:60]
            break
    return ([token] if token else ["jsonrpc"], "or")


# ── Raw HTTP request builder ─────────────────────────────────────────────────

def _host_from_target(target: str) -> str:
    """Best-effort host extraction from an MCP target URL/string."""
    if "://" in target:
        netloc = urlsplit(target).netloc
        if netloc:
            return netloc
    return "{{Hostname}}"


def _mcp_path(target: str) -> str:
    if "://" in target:
        path = urlsplit(target).path or "/mcp"
        return path or "/mcp"
    return "/mcp"


def _build_mcp_raw_request(target: str, method: str, params: dict) -> str:
    """Build a raw HTTP request block for a JSON-RPC call to the MCP server."""
    path = _mcp_path(target)
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        separators=(",", ":"),
    )
    return (
        f"POST {path} HTTP/1.1\n"
        "Host: {{Hostname}}\n"
        "Content-Type: application/json\n"
        "Accept: application/json, text/event-stream\n"
        "\n"
        f"{body}"
    )


# ── Template assembly ────────────────────────────────────────────────────────

def _build_request_for_finding(finding: Finding, target: str) -> str:
    """Choose the JSON-RPC method/params that reproduce the finding."""
    uri = _extract_uri_payload(finding)
    if uri is not None:
        return _build_mcp_raw_request(target, "resources/read", {"uri": uri})

    call = _extract_tool_call(finding)
    if call is not None:
        tool, args = call
        return _build_mcp_raw_request(
            target, "tools/call", {"name": tool, "arguments": args}
        )

    # No reproducible payload — fall back to a tools/list probe.
    return _build_mcp_raw_request(target, "tools/list", {})


def _yaml_dump(data: dict) -> str:
    if _HAVE_YAML:
        return yaml.safe_dump(data, sort_keys=False, default_flow_style=False,
                              allow_unicode=True, width=1000)
    return _manual_yaml(data)


def _manual_yaml(data: dict) -> str:
    """Minimal YAML emitter used when PyYAML is unavailable."""

    def esc(v: str) -> str:
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'

    lines: list[str] = []

    def emit(obj, indent: int) -> None:
        pad = "  " * indent
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    lines.append(f"{pad}{k}:")
                    emit(v, indent + 1)
                else:
                    lines.append(f"{pad}{k}: {_scalar(v)}")
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, dict):
                    # Render first key on the dash line.
                    keys = list(item.items())
                    first_k, first_v = keys[0]
                    if isinstance(first_v, (dict, list)):
                        lines.append(f"{pad}-")
                        emit(item, indent + 1)
                    else:
                        lines.append(f"{pad}- {first_k}: {_scalar(first_v)}")
                        emit(dict(keys[1:]), indent + 1)
                else:
                    lines.append(f"{pad}- {_scalar(item)}")

    def _scalar(v) -> str:
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, (int, float)):
            return str(v)
        s = str(v)
        if "\n" in s or '"' in s or ":" in s or s.strip() != s or not s:
            return esc(s)
        return s

    emit(data, 0)
    return "\n".join(lines) + "\n"


def finding_to_nuclei_template(finding: Finding, target: str) -> str:
    """Convert a single Finding to a Nuclei v3 YAML template string."""
    template_id = _finding_to_template_id(finding)
    words, condition = _matcher_words(finding)
    raw_request = _build_request_for_finding(finding, target)

    tags = sorted({"mcp", *[_slugify(t) for t in finding.tags if t]})

    template = {
        "id": template_id,
        "info": {
            "name": f"MCP: {finding.title}",
            "author": "mcpray",
            "severity": _severity_to_nuclei(finding.severity),
            "description": finding.impact or finding.title,
            "reference": ["https://github.com/your-org/mcpray"],
            "tags": ",".join(tags),
            "metadata": {
                "mcpray-finding-id": finding.id,
                "affected-component": finding.affected_component,
            },
        },
        "http": [
            {
                "raw": [raw_request],
                "matchers-condition": "and",
                "matchers": [
                    {"type": "status", "status": [200]},
                    {
                        "type": "word",
                        "part": "body",
                        "condition": condition,
                        "words": words,
                    },
                ],
            }
        ],
    }

    body = _yaml_dump(template)

    # Reproduction steps become a leading comment block — kept verbatim.
    steps = "\n".join(f"#   {s}" for s in finding.reproduction_steps)
    header = (
        f"# Auto-generated by mcpray from finding {finding.id}\n"
        f"# Affected: {finding.affected_component}\n"
        "# Reproduction steps:\n"
        f"{steps}\n"
        "#\n"
        f"# Run: nuclei -t {template_id}.yaml -u {target}\n"
    )
    return header + "\n" + body


# ── File / pack generation ───────────────────────────────────────────────────

def _qualifying(scan_result: ScanResult, min_severity: Severity) -> list[Finding]:
    floor = min_severity.numeric
    return [f for f in scan_result.findings if f.severity.numeric >= floor]


def _readme(target: str, files: list[tuple[str, Finding]]) -> str:
    lines = [
        "# mcpray — Nuclei Templates",
        "",
        f"Target: `{target}`",
        "",
        "These templates were generated from confirmed mcpray findings. They are",
        "runnable against the live MCP server (HTTP transport) and suitable for CI.",
        "",
        "## Run all templates",
        "",
        "```bash",
        f"nuclei -t . -u {target}",
        "```",
        "",
        "## Run a single template",
        "",
        "```bash",
        f"nuclei -t <file>.yaml -u {target}",
        "```",
        "",
        "## Templates",
        "",
    ]
    for fname, finding in files:
        lines.append(
            f"- `{fname}` — **{finding.severity.value}** — {finding.title}"
        )
    lines.append("")
    return "\n".join(lines)


def generate_nuclei_templates(
    scan_result: ScanResult,
    output_dir: str,
    min_severity: Severity = Severity.MEDIUM,
) -> list[str]:
    """Generate one ``.yaml`` file per qualifying finding plus a README index."""
    out = Path(output_dir) / "nuclei_templates"
    out.mkdir(parents=True, exist_ok=True)

    written: list[str] = []
    index: list[tuple[str, Finding]] = []
    used_ids: dict[str, int] = {}

    for finding in _qualifying(scan_result, min_severity):
        template_id = _finding_to_template_id(finding)
        # De-duplicate template ids across multiple similar findings.
        count = used_ids.get(template_id, 0)
        used_ids[template_id] = count + 1
        fname = f"{template_id}.yaml" if count == 0 else f"{template_id}-{count}.yaml"

        content = finding_to_nuclei_template(finding, scan_result.target)
        path = out / fname
        path.write_text(content, encoding="utf-8")
        written.append(str(path))
        index.append((fname, finding))

    readme = out / "README.md"
    readme.write_text(_readme(scan_result.target, index), encoding="utf-8")
    written.append(str(readme))

    return written


def save_nuclei_pack(
    scan_result: ScanResult,
    output_path: str,
    min_severity: Severity = Severity.MEDIUM,
) -> str:
    """Generate templates into a temp dir, zip them, and return the zip path."""
    out_zip = Path(output_path)
    if out_zip.suffix.lower() != ".zip":
        out_zip = out_zip.with_suffix(".zip")
    out_zip.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        files = generate_nuclei_templates(scan_result, tmp, min_severity)
        base = Path(tmp)
        with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in files:
                arcname = Path(f).relative_to(base)
                zf.write(f, str(arcname))

    return str(out_zip)
