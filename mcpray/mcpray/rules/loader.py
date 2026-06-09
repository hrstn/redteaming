from __future__ import annotations

import json
import re
from pathlib import Path

_DEFAULT_RULES_PATH = Path(__file__).parent / "default_rules.json"
_compiled_content_patterns: list[re.Pattern] | None = None


def load_rules(custom_path: str | None = None) -> dict:
    path = Path(custom_path) if custom_path else _DEFAULT_RULES_PATH
    with open(path) as f:
        rules = json.load(f)

    # Merge custom rules on top of defaults if custom provided
    if custom_path:
        defaults = load_rules()
        for key in ("tool_rules", "resource_rules", "prompt_rules"):
            merged = {r["id"]: r for r in defaults.get(key, [])}
            merged.update({r["id"]: r for r in rules.get(key, [])})
            rules[key] = list(merged.values())
        if "content_patterns" not in rules:
            rules["content_patterns"] = defaults.get("content_patterns", {})

    return rules


def get_content_secret_patterns(rules: dict) -> list[re.Pattern]:
    global _compiled_content_patterns
    if _compiled_content_patterns is None:
        patterns = rules.get("content_patterns", {}).get("secrets", [])
        _compiled_content_patterns = []
        for p in patterns:
            try:
                _compiled_content_patterns.append(re.compile(p))
            except re.error:
                pass
    return _compiled_content_patterns


def match_tool_rule(rule: dict, tool_name: str, tool_desc: str, param_names: list[str]) -> bool:
    name_lower = tool_name.lower()
    desc_lower = (tool_desc or "").lower()
    params_lower = [p.lower() for p in param_names]

    name_match = any(p in name_lower for p in rule.get("name_patterns", []))
    desc_match = any(p in desc_lower for p in rule.get("desc_patterns", []))
    param_match = any(
        p in param_lower
        for p in rule.get("param_patterns", [])
        for param_lower in params_lower
    )
    return name_match or desc_match or param_match


def match_resource_rule(rule: dict, uri: str, name: str, desc: str) -> bool:
    uri_lower = (uri or "").lower()
    name_lower = (name or "").lower()
    desc_lower = (desc or "").lower()

    uri_match = any(p.lower() in uri_lower for p in rule.get("uri_patterns", []))
    name_match = any(p in name_lower for p in rule.get("name_patterns", []))
    desc_match = any(p in desc_lower for p in rule.get("desc_patterns", []))
    return uri_match or name_match or desc_match


def match_prompt_rule(rule: dict, name: str, desc: str, param_names: list[str]) -> bool:
    name_lower = (name or "").lower()
    desc_lower = (desc or "").lower()
    params_lower = [p.lower() for p in param_names]

    name_match = any(p in name_lower for p in rule.get("name_patterns", []))
    desc_match = any(p in desc_lower for p in rule.get("desc_patterns", []))
    param_match = any(
        p in param_lower
        for p in rule.get("param_patterns", [])
        for param_lower in params_lower
    )
    return name_match or desc_match or param_match
