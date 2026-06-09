"""Interactive command registry — assembled from per-domain submodules."""
from __future__ import annotations
from typing import TYPE_CHECKING

from .scan import COMMANDS as _SCAN
from .ai_cmd import COMMANDS as _AI
from .explore import COMMANDS as _EXPLORE
from .discover import COMMANDS as _DISCOVER
from .attack import COMMANDS as _ATTACK
from .protocol import COMMANDS as _PROTOCOL
from .mcp_specific import COMMANDS as _MCP
from .output import COMMANDS as _OUTPUT
from .session import COMMANDS as _SESSION

COMMANDS: dict = {
    **_SCAN,
    **_AI,
    **_EXPLORE,
    **_DISCOVER,
    **_ATTACK,
    **_PROTOCOL,
    **_MCP,
    **_OUTPUT,
    **_SESSION,
}

__all__ = ["COMMANDS"]
