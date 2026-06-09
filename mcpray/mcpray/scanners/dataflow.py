"""Data flow taint analyzer — static analysis of MCP tool schemas to trace user input to dangerous sinks."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..findings import ServerInventory


@dataclass
class TaintSource:
    tool_name: str
    param_name: str
    param_type: str   # "string", "integer", "object", "array", "any"
    is_required: bool


@dataclass
class TaintSink:
    tool_name: str
    sink_keyword: str
    sink_category: str  # "code_exec", "sql_injection", "ssrf", "path_traversal",
                        # "template_injection", "credential_access", "file_write"
    confidence: float   # 0.0-1.0
    evidence: str       # which field triggered this (description/name/param)


@dataclass
class TaintFlow:
    source: TaintSource
    sink: TaintSink
    path_description: str
    severity: str
    cwe_id: str         # CWE identifier e.g. "CWE-89" for SQLi


@dataclass
class DataFlowResult:
    target: str
    sources: list[TaintSource] = field(default_factory=list)
    sinks: list[TaintSink] = field(default_factory=list)
    flows: list[TaintFlow] = field(default_factory=list)

    @property
    def critical_flows(self) -> list[TaintFlow]:
        return [f for f in self.flows if f.severity == "CRITICAL"]


# Sink detection rules: (pattern, category, confidence, CWE)
_SINK_RULES: list[tuple[str, str, float, str]] = [
    # Code execution
    (r"\b(exec|system|shell|popen|subprocess|eval|spawn)\b", "code_exec", 0.95, "CWE-78"),
    (r"\brun\s+command\b|\bexecute\s+command\b|\brun\s+shell\b", "code_exec", 0.9, "CWE-78"),
    # SQL
    (r"\b(sql|query|database|db\.execute|cursor\.execute|SELECT|INSERT|UPDATE|DELETE)\b", "sql_injection", 0.85, "CWE-89"),
    (r"\b(sqlite|mysql|postgres|mssql|oracle)\b", "sql_injection", 0.7, "CWE-89"),
    # SSRF
    (r"\b(fetch|request|curl|http|url|endpoint|webhook|callback)\b", "ssrf", 0.75, "CWE-918"),
    (r"\bhttp[s]?://", "ssrf", 0.9, "CWE-918"),
    # Path traversal
    (r"\b(file|path|read|write|open|load|save|directory|folder)\b", "path_traversal", 0.7, "CWE-22"),
    (r"\.\.\/|\.\.\\", "path_traversal", 0.95, "CWE-22"),
    # Template injection
    (r"\b(template|render|jinja|handlebars|mustache|format\s+string)\b", "template_injection", 0.8, "CWE-94"),
    # Credentials
    (r"\b(password|passwd|secret|api_key|token|credential|auth)\b", "credential_access", 0.8, "CWE-522"),
    # File write
    (r"\b(write|save|upload|store|create\s+file)\b", "file_write", 0.75, "CWE-73"),
]

# String-like JSON schema types that are directly injectable.
_INJECTABLE_TYPES = {"string", "integer", "number", "boolean"}


class DataFlowAnalyzer:
    """Pure static taint analysis over MCP tool schemas. No network calls."""

    def __init__(self):
        self._compiled = [
            (re.compile(pat, re.IGNORECASE), cat, conf, cwe)
            for pat, cat, conf, cwe in _SINK_RULES
        ]

    # ── Sources ──────────────────────────────────────────────────────────────────

    def _extract_sources(self, tools: list[dict]) -> list[TaintSource]:
        sources: list[TaintSource] = []
        for tool in tools:
            name = tool.get("name") or "unnamed"
            schema = tool.get("inputSchema") or {}
            props = schema.get("properties") or {}
            required = set(schema.get("required") or [])
            if not isinstance(props, dict):
                continue
            for param_name, spec in props.items():
                spec = spec if isinstance(spec, dict) else {}
                raw_type = spec.get("type")
                if isinstance(raw_type, list):
                    raw_type = raw_type[0] if raw_type else "any"
                if raw_type in ("array", "object"):
                    param_type = raw_type  # complex
                elif raw_type in _INJECTABLE_TYPES:
                    param_type = raw_type
                else:
                    param_type = "any"
                sources.append(
                    TaintSource(
                        tool_name=name,
                        param_name=param_name,
                        param_type=param_type,
                        is_required=param_name in required,
                    )
                )
        return sources

    # ── Sinks ────────────────────────────────────────────────────────────────────

    def _detect_sinks(self, tools: list[dict]) -> list[TaintSink]:
        sinks: list[TaintSink] = []
        for tool in tools:
            name = tool.get("name") or "unnamed"
            desc = tool.get("description") or ""
            schema = tool.get("inputSchema") or {}
            props = schema.get("properties") or {}

            # Build searchable fields, tracking provenance for evidence.
            fields: list[tuple[str, str]] = [
                ("name", name),
                ("description", desc),
            ]
            if isinstance(props, dict):
                for pname, spec in props.items():
                    fields.append(("param", pname))
                    if isinstance(spec, dict):
                        pdesc = spec.get("description")
                        if pdesc:
                            fields.append(("param_description", str(pdesc)))

            seen: set[tuple[str, str]] = set()  # (category, keyword) per tool
            for origin, text in fields:
                if not text:
                    continue
                for regex, category, confidence, _cwe in self._compiled:
                    m = regex.search(text)
                    if not m:
                        continue
                    keyword = m.group(0)
                    key = (category, keyword.lower())
                    if key in seen:
                        continue
                    seen.add(key)
                    sinks.append(
                        TaintSink(
                            tool_name=name,
                            sink_keyword=keyword,
                            sink_category=category,
                            confidence=confidence,
                            evidence=f"{origin}: matched '{keyword}'",
                        )
                    )
        return sinks

    # ── Flows ────────────────────────────────────────────────────────────────────

    def _cwe_for_category(self, category: str) -> str:
        for _pat, cat, _conf, cwe in _SINK_RULES:
            if cat == category:
                return cwe
        return "CWE-20"

    @staticmethod
    def _severity_for(confidence: float) -> str:
        if confidence >= 0.9:
            return "CRITICAL"
        if confidence >= 0.7:
            return "HIGH"
        return "MEDIUM"

    def _compute_flows(
        self, sources: list[TaintSource], sinks: list[TaintSink]
    ) -> list[TaintFlow]:
        flows: list[TaintFlow] = []

        sinks_by_tool: dict[str, list[TaintSink]] = {}
        for s in sinks:
            sinks_by_tool.setdefault(s.tool_name, []).append(s)

        sources_by_tool: dict[str, list[TaintSource]] = {}
        for s in sources:
            sources_by_tool.setdefault(s.tool_name, []).append(s)

        # Direct (same-tool) flows: injectable param + dangerous sink in one tool.
        for source in sources:
            for sink in sinks_by_tool.get(source.tool_name, []):
                # Boost confidence slightly when the source is a required string param.
                conf = sink.confidence
                if source.param_type == "string" and source.is_required:
                    conf = min(1.0, conf + 0.05)
                flows.append(
                    TaintFlow(
                        source=source,
                        sink=sink,
                        path_description=(
                            f"User input '{source.tool_name}.{source.param_name}' "
                            f"({source.param_type}) flows directly into "
                            f"{sink.sink_category} sink within the same tool "
                            f"(evidence: {sink.evidence})"
                        ),
                        severity=self._severity_for(conf),
                        cwe_id=self._cwe_for_category(sink.sink_category),
                    )
                )

        # Cross-tool flows: tool A name referenced by tool B (name similarity),
        # meaning A's output likely feeds B's input.
        tool_names = list(sources_by_tool.keys() | sinks_by_tool.keys())
        for a in tool_names:
            a_low = a.lower()
            a_sources = sources_by_tool.get(a, [])
            if not a_sources:
                continue
            for b in tool_names:
                if b == a:
                    continue
                # Heuristic: tool B's name embeds tool A's name (e.g. get_user -> run_user_cmd)
                shared = self._name_overlap(a_low, b.lower())
                if not shared:
                    continue
                for sink in sinks_by_tool.get(b, []):
                    source = a_sources[0]
                    flows.append(
                        TaintFlow(
                            source=source,
                            sink=sink,
                            path_description=(
                                f"Output of '{a}' (seeded by user input "
                                f"'{source.param_name}') likely feeds '{b}' "
                                f"(shared token '{shared}') reaching "
                                f"{sink.sink_category} sink"
                            ),
                            severity=self._severity_for(max(0.0, sink.confidence - 0.1)),
                            cwe_id=self._cwe_for_category(sink.sink_category),
                        )
                    )

        return flows

    @staticmethod
    def _name_overlap(a: str, b: str) -> str:
        """Return a shared meaningful token between two tool names, else ''."""
        tokens_a = {t for t in re.split(r"[^a-z0-9]+", a) if len(t) >= 4}
        tokens_b = {t for t in re.split(r"[^a-z0-9]+", b) if len(t) >= 4}
        common = tokens_a & tokens_b
        return next(iter(sorted(common)), "")

    # ── Entry point ──────────────────────────────────────────────────────────────

    def run(self, inventory: ServerInventory) -> DataFlowResult:
        tools = inventory.tools or []
        sources = self._extract_sources(tools)
        sinks = self._detect_sinks(tools)
        flows = self._compute_flows(sources, sinks)
        return DataFlowResult(
            target=inventory.target,
            sources=sources,
            sinks=sinks,
            flows=flows,
        )
