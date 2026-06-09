from __future__ import annotations

from abc import ABC, abstractmethod

from ..client import MCPClient
from ..findings import Finding, ServerInventory


class BaseScanner(ABC):
    """All scanner plugins inherit from this."""

    name: str = "base"

    def __init__(self, client: MCPClient, rules: dict):
        self.client = client
        self.rules = rules
        self._findings: list[Finding] = []
        self._finding_counter = 0

    def _next_id(self) -> str:
        self._finding_counter += 1
        return f"{self.name.upper()}-{self._finding_counter:03d}"

    @abstractmethod
    async def scan(self, inventory: ServerInventory) -> list[Finding]:
        """Run all checks and return findings."""
        ...

    def findings(self) -> list[Finding]:
        return list(self._findings)
