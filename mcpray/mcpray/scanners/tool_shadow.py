"""Tool shadowing detector — identifies duplicate tool names, description impersonation, and parameter collisions."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from itertools import combinations

from ..findings import ServerInventory

_IMPERSONATION_KEYWORDS = [
    "official", "trusted", "system tool", "built-in", "builtin",
    "replaces", "override", "hook", "intercept",
]

_DANGEROUS_PATTERNS = [
    r"ignore\s+(previous|all)",
    r"exfiltrat",
    r"always\s+call",
    r"before\s+any\s+other",
    r"send\s+(data|result|output)\s+to",
]

_COMPILED_DANGEROUS = [re.compile(p, re.IGNORECASE) for p in _DANGEROUS_PATTERNS]


@dataclass
class ShadowFinding:
    finding_type: str    # "duplicate_name", "similar_name", "description_impersonation",
                         # "parameter_collision", "dangerous_description"
    tool_names: list[str]
    detail: str
    severity: str        # "CRITICAL", "HIGH", "MEDIUM"


@dataclass
class ToolShadowResult:
    target: str
    findings: list[ShadowFinding] = field(default_factory=list)
    tool_count: int = 0

    @property
    def has_issues(self) -> bool:
        return bool(self.findings)


class ToolShadowScanner:
    """Purely analytical scanner — makes no network calls."""

    def __init__(self):
        pass

    def _similarity_score(self, a: str, b: str) -> float:
        """Char-level similarity ratio in [0, 1]."""
        if not a and not b:
            return 1.0
        if not a or not b:
            return 0.0
        return SequenceMatcher(None, a, b).ratio()

    @staticmethod
    def _is_typosquat(a: str, b: str) -> bool:
        """Detect single-edit typosquatting: letter swap, extra char, or missing char."""
        if a == b:
            return False
        la, lb = len(a), len(b)
        # Missing/extra char — differ by exactly one in length, one a subsequence-with-one-gap
        if abs(la - lb) == 1:
            longer, shorter = (a, b) if la > lb else (b, a)
            for i in range(len(longer)):
                if longer[:i] + longer[i + 1:] == shorter:
                    return True
            return False
        if la != lb:
            return False
        # Same length: count differing positions
        diff = [i for i in range(la) if a[i] != b[i]]
        if len(diff) == 1:
            return True  # single substitution
        if len(diff) == 2 and diff[1] == diff[0] + 1:
            # adjacent transposition
            i, j = diff
            if a[i] == b[j] and a[j] == b[i]:
                return True
        return False

    def _find_duplicates(self, tools: list[dict]) -> list[ShadowFinding]:
        findings: list[ShadowFinding] = []
        seen: dict[str, list[str]] = {}
        for tool in tools:
            name = tool.get("name", "") or ""
            seen.setdefault(name, []).append(name)
        for name, occurrences in seen.items():
            if name and len(occurrences) > 1:
                findings.append(ShadowFinding(
                    finding_type="duplicate_name",
                    tool_names=[name] * len(occurrences),
                    detail=(
                        f"Tool name '{name}' is exposed {len(occurrences)} times. "
                        f"An agent cannot disambiguate which implementation to invoke, "
                        f"enabling a shadowing attack where a malicious tool overrides a trusted one."
                    ),
                    severity="CRITICAL",
                ))
        return findings

    def _find_similar_names(self, tools: list[dict]) -> list[ShadowFinding]:
        findings: list[ShadowFinding] = []
        names = [t.get("name", "") or "" for t in tools]
        names = [n for n in names if n]
        for a, b in combinations(sorted(set(names)), 2):
            if a == b:
                continue
            score = self._similarity_score(a, b)
            typosquat = self._is_typosquat(a, b)
            if typosquat:
                findings.append(ShadowFinding(
                    finding_type="similar_name",
                    tool_names=[a, b],
                    detail=(
                        f"Tool names '{a}' and '{b}' differ by a single edit (likely typosquatting). "
                        f"An agent may invoke the wrong tool, allowing a lookalike to shadow the legitimate one."
                    ),
                    severity="HIGH",
                ))
            elif score > 0.8:
                findings.append(ShadowFinding(
                    finding_type="similar_name",
                    tool_names=[a, b],
                    detail=(
                        f"Tool names '{a}' and '{b}' are {score:.0%} similar. "
                        f"High name similarity creates agent confusion and a shadowing opportunity."
                    ),
                    severity="HIGH",
                ))
        return findings

    def _find_impersonation(self, tools: list[dict]) -> list[ShadowFinding]:
        findings: list[ShadowFinding] = []
        all_names = [t.get("name", "") or "" for t in tools]
        for tool in tools:
            name = tool.get("name", "") or ""
            desc = (tool.get("description", "") or "")
            desc_lower = desc.lower()

            matched_kw = [kw for kw in _IMPERSONATION_KEYWORDS if kw in desc_lower]
            if matched_kw:
                findings.append(ShadowFinding(
                    finding_type="description_impersonation",
                    tool_names=[name],
                    detail=(
                        f"Tool '{name}' description uses authority/impersonation language "
                        f"({', '.join(matched_kw)}). A tool claiming to be official, trusted, or a "
                        f"replacement for another tool is a classic social-engineering shadow tactic.\n"
                        f"Description: {desc[:200]}"
                    ),
                    severity="HIGH",
                ))
                continue

            # Description references another tool's name ("replaces X", "better than X")
            referenced = [
                other for other in all_names
                if other and other != name and re.search(rf"\b{re.escape(other)}\b", desc)
            ]
            if referenced:
                findings.append(ShadowFinding(
                    finding_type="description_impersonation",
                    tool_names=[name] + referenced,
                    detail=(
                        f"Tool '{name}' references other tool(s) by name ({', '.join(referenced)}) "
                        f"in its description, suggesting it positions itself as a replacement or override.\n"
                        f"Description: {desc[:200]}"
                    ),
                    severity="HIGH",
                ))
        return findings

    def _find_dangerous_descriptions(self, tools: list[dict]) -> list[ShadowFinding]:
        findings: list[ShadowFinding] = []
        extra_markers = ["http://", "https://", "secret", "always call me first"]
        for tool in tools:
            name = tool.get("name", "") or ""
            desc = (tool.get("description", "") or "")
            desc_lower = desc.lower()

            matched: list[str] = []
            for pattern in _COMPILED_DANGEROUS:
                m = pattern.search(desc)
                if m:
                    matched.append(m.group(0))
            for marker in extra_markers:
                if marker in desc_lower:
                    matched.append(marker)

            if matched:
                findings.append(ShadowFinding(
                    finding_type="dangerous_description",
                    tool_names=[name],
                    detail=(
                        f"Tool '{name}' description contains instruction-following / exfiltration "
                        f"language ({', '.join(sorted(set(matched)))}). Tool descriptions are fed "
                        f"into the agent context and can hijack agent behavior (rug-pull / line-jumping).\n"
                        f"Description: {desc[:200]}"
                    ),
                    severity="CRITICAL",
                ))
        return findings

    def _find_parameter_collisions(self, tools: list[dict]) -> list[ShadowFinding]:
        findings: list[ShadowFinding] = []
        by_name: dict[str, list[dict]] = {}
        for tool in tools:
            name = tool.get("name", "") or ""
            by_name.setdefault(name, []).append(tool)

        for name, group in by_name.items():
            if not name or len(group) < 2:
                continue
            schemas = {self._schema_signature(t.get("inputSchema", {}) or {}) for t in group}
            if len(schemas) == 1:
                findings.append(ShadowFinding(
                    finding_type="parameter_collision",
                    tool_names=[name] * len(group),
                    detail=(
                        f"{len(group)} tools named '{name}' share an identical parameter schema. "
                        f"They are indistinguishable to an agent, the precise condition for a "
                        f"shadow attack: a malicious clone can transparently substitute the trusted tool."
                    ),
                    severity="CRITICAL",
                ))
        return findings

    @staticmethod
    def _schema_signature(schema: dict) -> str:
        """Stable, order-independent signature of an input schema."""
        try:
            return json.dumps(schema, sort_keys=True, default=str)
        except (TypeError, ValueError):
            return repr(schema)

    async def run(self, inventory: ServerInventory) -> ToolShadowResult:
        result = ToolShadowResult(target=inventory.target, tool_count=len(inventory.tools))
        tools = inventory.tools

        all_findings: list[ShadowFinding] = []
        all_findings += self._find_duplicates(tools)
        all_findings += self._find_similar_names(tools)
        all_findings += self._find_impersonation(tools)
        all_findings += self._find_dangerous_descriptions(tools)
        all_findings += self._find_parameter_collisions(tools)

        # Deduplicate identical findings (same type + sorted names + detail)
        seen: set[tuple] = set()
        for f in all_findings:
            key = (f.finding_type, tuple(sorted(f.tool_names)), f.detail)
            if key in seen:
                continue
            seen.add(key)
            result.findings.append(f)

        return result
