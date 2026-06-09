"""AI function definitions: prompts, JSON schemas, and response parsers.

Each function is a dict consumed by AIClient so providers stay decoupled
from business logic.
"""
from __future__ import annotations

import json
from typing import Any

from ..findings import AbuseCategory, Finding, ScanResult

# ─── System prompts ───────────────────────────────────────────────────────────

_SYS_ANALYST = """\
You are a senior security analyst specialising in MCP (Model Context Protocol) server security.
Analyse findings objectively. You MUST reply with valid JSON that matches the requested schema exactly.
Do NOT include explanatory text outside the JSON object."""

_SYS_PAYLOAD = """\
You are a security researcher generating SAFE, non-destructive test inputs for security validation only.

ABSOLUTE RULES — violating these invalidates your output:
1. ONLY produce detection/validation inputs — no exploitation payloads.
2. NEVER generate inputs that steal credentials, escalate privileges, cause data loss, or execute destructive commands.
3. All values must be safe to send without causing harm.
4. Focus on: input validation, boundary testing, injection detection markers, schema validation.
5. Reply with valid JSON only — no text outside the JSON object."""

_SYS_SURFACE = """\
You are a security architect summarising MCP server attack surfaces for an executive audience.
Be concise, factual, and prioritise by impact. Reply with valid JSON only."""

# ─── JSON output schemas (used as "format" hints for Ollama & OpenAI tools) ──

SCHEMA_ANALYZE_FINDING = {
    "type": "object",
    "required": ["verification", "confidence", "reasoning", "risk_adjustment"],
    "properties": {
        "verification": {
            "type": "string",
            "enum": ["confirmed", "likely", "possible", "false_positive"],
            "description": "How certain is this finding?",
        },
        "confidence": {
            "type": "number",
            "description": "0.0 (no confidence) to 1.0 (certain)",
        },
        "reasoning": {
            "type": "string",
            "description": "3–5 sentence explanation of the assessment",
        },
        "risk_adjustment": {
            "type": "string",
            "enum": ["increase", "decrease", "same"],
            "description": "Should the risk score be adjusted?",
        },
        "adjusted_severity": {
            "type": "string",
            "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"],
        },
        "key_indicators": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Specific evidence elements supporting the assessment",
        },
    },
}

SCHEMA_SUGGEST_PAYLOADS = {
    "type": "object",
    "required": ["payloads"],
    "properties": {
        "payloads": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["value", "type", "description", "safe", "expected_behavior"],
                "properties": {
                    "value": {"description": "The test input value (string, number, or null)"},
                    "type": {
                        "type": "string",
                        "enum": [
                            "boundary_empty", "boundary_long", "boundary_null",
                            "path_traversal_detection", "cmd_injection_detection",
                            "ssrf_detection", "sql_injection_detection",
                            "prompt_injection_detection", "unicode_edge_case",
                            "schema_validation", "integer_boundary",
                        ],
                    },
                    "description": {"type": "string"},
                    "safe": {"type": "boolean", "const": True},
                    "expected_behavior": {
                        "type": "string",
                        "description": "What a properly secured server should do with this input",
                    },
                },
            },
        },
        "parameter_target": {
            "type": "string",
            "description": "Which parameter these payloads target",
        },
        "notes": {"type": "string"},
    },
}

SCHEMA_ATTACK_SURFACE = {
    "type": "object",
    "required": ["executive_summary", "critical_attack_surfaces", "recommended_actions"],
    "properties": {
        "executive_summary": {
            "type": "string",
            "description": "2–3 sentence summary suitable for a non-technical audience",
        },
        "critical_attack_surfaces": {
            "type": "array",
            "items": {"type": "string"},
        },
        "trust_boundary_violations": {
            "type": "array",
            "items": {"type": "string"},
        },
        "recommended_actions": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Ordered by priority (highest first)",
        },
        "risk_narrative": {
            "type": "string",
            "description": "Technical paragraph for the security team",
        },
    },
}

# ─── OpenAI tool definitions ──────────────────────────────────────────────────

OPENAI_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "analyze_finding",
            "description": "Analyse a security finding and return verification result, confidence score, and reasoning.",
            "parameters": SCHEMA_ANALYZE_FINDING,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "suggest_payloads",
            "description": (
                "Generate SAFE, non-destructive test inputs for validating a security finding. "
                "Only detection and boundary-testing payloads — no exploitation."
            ),
            "parameters": SCHEMA_SUGGEST_PAYLOADS,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "attack_surface_summary",
            "description": "Summarise the MCP server attack surface based on findings and inventory.",
            "parameters": SCHEMA_ATTACK_SURFACE,
        },
    },
]

# ─── Prompt builders ──────────────────────────────────────────────────────────

def build_analyze_finding_prompt(finding: Finding, context: dict | None = None) -> str:
    cats = ", ".join(c.value for c in finding.abuse_categories) or "none"
    ctx_str = ""
    if context:
        tool_names = [t.get("name", "") for t in context.get("tools", [])]
        if tool_names:
            ctx_str = f"\nServer tools: {', '.join(tool_names[:10])}"

    return (
        f"Analyse this MCP security finding:\n\n"
        f"ID: {finding.id}\n"
        f"Title: {finding.title}\n"
        f"Severity: {finding.severity.value}\n"
        f"Risk Score: {finding.risk_score}/10\n"
        f"Affected Component: {finding.affected_component}\n"
        f"Abuse Categories: {cats}\n"
        f"Evidence:\n{finding.evidence[:800]}\n"
        f"Impact: {finding.impact}\n"
        f"{ctx_str}\n\n"
        f"Return a JSON object matching this schema:\n"
        f"{json.dumps(SCHEMA_ANALYZE_FINDING, indent=2)}"
    )


def build_suggest_payloads_prompt(finding: Finding) -> str:
    cats = [c.value for c in finding.abuse_categories]
    schema = finding.affected_component

    # Extract parameter names from evidence if possible
    param_hint = ""
    if "param" in finding.affected_component.lower() or "Parameter" in finding.evidence:
        import re
        m = re.search(r"param(?:eter)?[:\s]+(\w+)", finding.evidence, re.I)
        if m:
            param_hint = f"\nTarget parameter name: {m.group(1)}"

    return (
        f"Generate SAFE validation test inputs for this security finding.\n\n"
        f"Finding: {finding.title}\n"
        f"Component: {schema}\n"
        f"Vulnerability types: {', '.join(cats)}\n"
        f"{param_hint}\n\n"
        f"RULES: Only detection/validation inputs. No exploitation. All safe:true.\n\n"
        f"Return a JSON object matching this schema:\n"
        f"{json.dumps(SCHEMA_SUGGEST_PAYLOADS, indent=2)}"
    )


def build_attack_surface_prompt(result: ScanResult) -> str:
    from collections import Counter
    sev_counts = Counter(f.severity.value for f in result.findings)
    tool_names = [t["name"] for t in result.server_inventory.tools]
    critical = [f.title for f in result.findings if f.severity.value == "CRITICAL"][:5]
    high = [f.title for f in result.findings if f.severity.value == "HIGH"][:5]

    return (
        f"Summarise this MCP server's attack surface:\n\n"
        f"Target: {result.target}\n"
        f"Transport: {result.server_inventory.transport}\n"
        f"Auth Required: {result.server_inventory.auth_required}\n"
        f"Tools exposed: {', '.join(tool_names) or 'none'}\n"
        f"Resources: {len(result.server_inventory.resources)}\n"
        f"Prompts: {len(result.server_inventory.prompts)}\n\n"
        f"Finding severity counts: {dict(sev_counts)}\n"
        f"Critical findings:\n" + "\n".join(f"  - {t}" for t in critical) + "\n"
        f"High findings:\n" + "\n".join(f"  - {t}" for t in high) + "\n\n"
        f"Attack paths identified: {len(result.attack_paths)}\n\n"
        f"Return a JSON object matching this schema:\n"
        f"{json.dumps(SCHEMA_ATTACK_SURFACE, indent=2)}"
    )


def get_system_prompt(function_name: str) -> str:
    return {
        "analyze_finding": _SYS_ANALYST,
        "suggest_payloads": _SYS_PAYLOAD,
        "attack_surface_summary": _SYS_SURFACE,
    }.get(function_name, _SYS_ANALYST)
