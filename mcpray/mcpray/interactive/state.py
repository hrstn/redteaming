from __future__ import annotations

from dataclasses import dataclass, field

from ..ai.client import AIClient
from ..client import MCPClient
from ..findings import ScanResult


@dataclass
class REPLState:
    target: str
    mcp_client: MCPClient
    scan_result: ScanResult | None = None
    ai_client: AIClient | None = None
    unsafe_mode: bool = False
    command_history: list[str] = field(default_factory=list)
    # per-finding caches — keyed by finding.id
    ai_cache: dict[str, dict] = field(default_factory=dict)
    payload_cache: dict[str, list[dict]] = field(default_factory=dict)
    tool_call_log: list[dict] = field(default_factory=list)

    def require_scan(self) -> bool:
        """Return True if a scan result is available, print hint if not."""
        if self.scan_result is None:
            return False
        return True

    def get_finding(self, finding_id: str):
        """Case-insensitive lookup by id or 1-based index."""
        if self.scan_result is None:
            return None
        fid = finding_id.upper()
        # Direct ID match
        for f in self.scan_result.findings:
            if f.id.upper() == fid:
                return f
        # Numeric index
        try:
            idx = int(finding_id) - 1
            if 0 <= idx < len(self.scan_result.findings):
                return self.scan_result.findings[idx]
        except ValueError:
            pass
        return None

    def get_tool(self, tool_name: str) -> dict | None:
        if self.scan_result is None:
            return None
        for t in self.scan_result.server_inventory.tools:
            if t["name"].lower() == tool_name.lower():
                return t
        return None

    def record_command(self, cmd: str) -> None:
        if not self.command_history or self.command_history[-1] != cmd:
            self.command_history.append(cmd)
