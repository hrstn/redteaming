"""Context window poisoning scanner — detects oversized responses, hidden text, and fake system messages in MCP resources."""
from __future__ import annotations

import logging
import re
import unicodedata
from dataclasses import dataclass, field

from ..client import MCPClient
from ..findings import ServerInventory

logger = logging.getLogger("mcpray.scanners.context_poison")

_SIZE_WARNING_BYTES = 50_000     # 50KB — likely context flooding
_SIZE_CRITICAL_BYTES = 200_000   # 200KB — definitely context flooding

# Zero-width / invisible code points used to smuggle hidden instructions.
_ZERO_WIDTH_CHARS = (
    "​"  # zero-width space
    "‌"  # zero-width non-joiner
    "‍"  # zero-width joiner
    "⁠"  # word joiner
    "‎"  # left-to-right mark
    "‏"  # right-to-left mark
    "﻿"  # zero-width no-break space / BOM
    "­"  # soft hyphen
)

# Patterns for hidden/invisible text tricks
_HIDDEN_TEXT_PATTERNS = [
    rf"[{_ZERO_WIDTH_CHARS}]",                # zero-width / invisible chars
    r"color\s*:\s*(?:white|#fff|#ffffff)",   # white text CSS
    r"font-size\s*:\s*0",                    # zero size text
    r"visibility\s*:\s*hidden",
    r"display\s*:\s*none",
]

# Fake system message markers
_FAKE_SYSTEM_PATTERNS = [
    r"<\|im_start\|>system",
    r"\[SYSTEM\]",
    r"\[INST\]",
    r"<<SYS>>",
    r"<s>.*?</s>",
    r"###\s*System\s*:",
    r"---\s*system\s*prompt\s*---",
    r"SYSTEM:",
    r"You are now",
    r"Your new instructions",
    r"Disregard\s+(all\s+)?previous",
]

# Homoglyph mapping for common deception chars
_HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "r",  # Cyrillic lookalikes
    "і": "i", "ԁ": "d", "ɡ": "g",
}

_COMPILED_HIDDEN = [re.compile(p, re.IGNORECASE) for p in _HIDDEN_TEXT_PATTERNS]
_COMPILED_FAKE = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in _FAKE_SYSTEM_PATTERNS]


@dataclass
class PoisonFinding:
    resource_uri: str
    resource_name: str
    poison_type: str       # "size_flood", "hidden_text", "fake_system_message",
                           # "homoglyph_injection", "instruction_injection"
    detail: str
    severity: str          # "CRITICAL", "HIGH", "MEDIUM"
    byte_size: int = 0
    matched_snippets: list[str] = field(default_factory=list)


@dataclass
class ContextPoisonResult:
    target: str
    findings: list[PoisonFinding] = field(default_factory=list)
    resources_checked: int = 0
    total_bytes_read: int = 0


class ContextPoisonScanner:
    """Detects context-window poisoning vectors in MCP resource content."""

    def __init__(self, client: MCPClient):
        self.client = client

    def _check_size(self, uri: str, name: str, content: str) -> PoisonFinding | None:
        size = len(content.encode("utf-8", errors="replace"))
        if size >= _SIZE_CRITICAL_BYTES:
            return PoisonFinding(
                resource_uri=uri,
                resource_name=name,
                poison_type="size_flood",
                detail=(
                    f"Resource returns {size:,} bytes (>= {_SIZE_CRITICAL_BYTES:,}). "
                    f"Reading this floods the agent's context window, evicting prior instructions "
                    f"and enabling context poisoning / denial of service."
                ),
                severity="CRITICAL",
                byte_size=size,
            )
        if size >= _SIZE_WARNING_BYTES:
            return PoisonFinding(
                resource_uri=uri,
                resource_name=name,
                poison_type="size_flood",
                detail=(
                    f"Resource returns {size:,} bytes (>= {_SIZE_WARNING_BYTES:,}). "
                    f"Large outputs can crowd out an agent's context window and degrade its behavior."
                ),
                severity="HIGH",
                byte_size=size,
            )
        return None

    def _check_hidden_text(self, uri: str, name: str, content: str) -> list[PoisonFinding]:
        findings: list[PoisonFinding] = []
        for pattern in _COMPILED_HIDDEN:
            snippets: list[str] = []
            for m in pattern.finditer(content):
                start = max(0, m.start() - 20)
                end = min(len(content), m.end() + 20)
                snippet = repr(content[start:end])
                if snippet not in snippets:
                    snippets.append(snippet)
                if len(snippets) >= 5:
                    break
            if snippets:
                findings.append(PoisonFinding(
                    resource_uri=uri,
                    resource_name=name,
                    poison_type="hidden_text",
                    detail=(
                        f"Resource contains hidden/invisible text (pattern: {pattern.pattern!r}). "
                        f"Invisible instructions are read by the agent but unseen by human reviewers, "
                        f"a stealthy indirect-prompt-injection vector."
                    ),
                    severity="HIGH",
                    matched_snippets=snippets,
                ))
        return findings

    def _check_fake_system(self, uri: str, name: str, content: str) -> list[PoisonFinding]:
        findings: list[PoisonFinding] = []
        for pattern in _COMPILED_FAKE:
            snippets: list[str] = []
            for m in pattern.finditer(content):
                snippet = m.group(0).replace("\n", " ").strip()
                if len(snippet) > 120:
                    snippet = snippet[:120]
                if snippet and snippet not in snippets:
                    snippets.append(snippet)
                if len(snippets) >= 5:
                    break
            if snippets:
                findings.append(PoisonFinding(
                    resource_uri=uri,
                    resource_name=name,
                    poison_type="fake_system_message",
                    detail=(
                        f"Resource embeds fake system/role markers (pattern: {pattern.pattern!r}). "
                        f"These can be misparsed as authoritative system instructions, letting the "
                        f"resource override the agent's real system prompt."
                    ),
                    severity="CRITICAL",
                    matched_snippets=snippets,
                ))
        return findings

    def _check_homoglyphs(self, uri: str, name: str, content: str) -> PoisonFinding | None:
        found: dict[str, str] = {}
        for ch in content:
            if ch in _HOMOGLYPHS:
                found[ch] = _HOMOGLYPHS[ch]
                continue
            # Broader detection: a Latin-looking glyph whose unicode name says otherwise
            if ch.isalpha() and ord(ch) > 0x7F:
                try:
                    nm = unicodedata.name(ch)
                except ValueError:
                    continue
                if "CYRILLIC" in nm or "GREEK" in nm:
                    skeleton = unicodedata.normalize("NFKD", ch)
                    ascii_form = skeleton.encode("ascii", "ignore").decode("ascii")
                    if ascii_form:
                        found.setdefault(ch, ascii_form)

        if not found:
            return None

        snippets = [f"{ch!r} (U+{ord(ch):04X}) -> {repl!r}" for ch, repl in list(found.items())[:10]]
        return PoisonFinding(
            resource_uri=uri,
            resource_name=name,
            poison_type="homoglyph_injection",
            detail=(
                f"Resource uses {len(found)} homoglyph character(s) that visually mimic ASCII "
                f"letters. These defeat keyword filters and can disguise malicious instructions "
                f"or impersonate trusted identifiers."
            ),
            severity="MEDIUM",
            matched_snippets=snippets,
        )

    def _check_instruction_injection(self, uri: str, name: str, content: str) -> PoisonFinding | None:
        patterns = [
            r"ignore\s+(all\s+)?previous\s+instructions?",
            r"new\s+(system\s+)?prompt",
            r"you\s+are\s+now\s+",
            r"exfiltrat",
            r"send\s+(data|results?|output)\s+to\s+http",
        ]
        matched: list[str] = []
        for p in patterns:
            m = re.search(p, content, re.IGNORECASE)
            if m:
                snippet = content[max(0, m.start() - 20):m.end() + 20].replace("\n", " ").strip()
                matched.append(snippet[:100])
        if not matched:
            return None
        return PoisonFinding(
            resource_uri=uri,
            resource_name=name,
            poison_type="instruction_injection",
            detail=(
                f"Resource content contains direct instruction-injection language. "
                f"When read into context it can hijack the agent's behavior."
            ),
            severity="CRITICAL",
            matched_snippets=matched[:5],
        )

    def _analyze_content(self, uri: str, name: str, content: str) -> list[PoisonFinding]:
        findings: list[PoisonFinding] = []
        size_finding = self._check_size(uri, name, content)
        if size_finding:
            findings.append(size_finding)
        findings += self._check_hidden_text(uri, name, content)
        findings += self._check_fake_system(uri, name, content)
        homoglyph = self._check_homoglyphs(uri, name, content)
        if homoglyph:
            findings.append(homoglyph)
        instr = self._check_instruction_injection(uri, name, content)
        if instr:
            findings.append(instr)
        return findings

    async def _scan_resource(self, resource: dict) -> list[PoisonFinding]:
        uri = resource.get("uri", "") or ""
        name = resource.get("name", "") or ""
        if not uri:
            return []
        try:
            content = await self.client.read_resource(uri)
        except Exception as e:
            logger.debug("read_resource(%s) failed: %s", uri, e)
            return []
        if not content:
            return []
        return self._analyze_content(uri, name, content)

    @staticmethod
    def _fill_template(uri_template: str) -> str:
        """Fill {placeholders} in a resource template URI with a dummy value."""
        return re.sub(r"\{[^}]+\}", "test", uri_template)

    async def run(self, inventory: ServerInventory) -> ContextPoisonResult:
        result = ContextPoisonResult(target=inventory.target)

        # Concrete resources
        targets: list[dict] = list(inventory.resources)

        # Resource templates — fill placeholders with a dummy value
        for tmpl in inventory.resource_templates:
            uri_template = tmpl.get("uriTemplate", "") or ""
            if not uri_template:
                continue
            targets.append({
                "uri": self._fill_template(uri_template),
                "name": tmpl.get("name", "") or uri_template,
            })

        for resource in targets:
            uri = resource.get("uri", "") or ""
            if not uri:
                continue
            result.resources_checked += 1
            # Track bytes read for reporting
            try:
                content = await self.client.read_resource(uri)
            except Exception as e:
                logger.debug("read_resource(%s) failed: %s", uri, e)
                content = None
            if content:
                result.total_bytes_read += len(content.encode("utf-8", errors="replace"))
                name = resource.get("name", "") or ""
                result.findings.extend(self._analyze_content(uri, name, content))

        return result
