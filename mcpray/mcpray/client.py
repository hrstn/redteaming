from __future__ import annotations

import logging
from typing import Any

import httpx
from fastmcp import Client

from .findings import ServerInventory

logger = logging.getLogger("mcpray.client")


def _extract_resource_text(result: Any) -> str | None:
    """Normalise all fastmcp read_resource return shapes to a plain string.

    fastmcp may return:
      - A ReadResourceResult with .contents (list of ResourceContents)
      - A bare list of ResourceContents objects
      - A single ResourceContents object
      - None / falsy
    Each ResourceContents may be TextResourceContents (.text) or
    BlobResourceContents (.blob, base64-encoded bytes).
    """
    if not result:
        return None

    parts: list[str] = []

    # Shape 1: object with .contents attribute
    items = getattr(result, "contents", None)
    # Shape 2: result is itself a list
    if items is None and isinstance(result, list):
        items = result
    # Shape 3: result is a single resource-content object
    if items is None:
        items = [result]

    for item in items:
        text = getattr(item, "text", None)
        if text is not None:
            parts.append(str(text))
            continue
        # BlobResourceContents — decode base64 to a hex summary
        blob = getattr(item, "blob", None)
        if blob is not None:
            import base64
            try:
                raw = base64.b64decode(blob)
                parts.append(raw.decode("utf-8", errors="replace"))
            except Exception:
                parts.append(f"<binary blob {len(blob)} base64 chars>")
            continue
        # Fallback for unknown shapes — skip repr noise
        inner = getattr(item, "content", None) or getattr(item, "data", None)
        if isinstance(inner, str):
            parts.append(inner)

    return "\n".join(parts) if parts else None


class MCPClient:
    """Thin wrapper around fastmcp Client with inventory + auth probing."""

    def __init__(
        self,
        target: str,
        headers: dict[str, str] | None = None,
        timeout: int = 30,
    ):
        self.target = target
        self.headers = headers or {}
        self.timeout = timeout
        self._client: Client | None = None
        self.auth_required: bool = False
        self.transport: str = self._detect_transport(target)

    @staticmethod
    def _detect_transport(target: str) -> str:
        if target.startswith("https://"):
            return "HTTPS"
        if target.startswith("http://"):
            return "HTTP (INSECURE)"
        if target.startswith("stdio:") or target.startswith("python") or target.endswith(".py"):
            return "STDIO"
        return "UNKNOWN"

    async def __aenter__(self) -> "MCPClient":
        self._client = Client(self.target)
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._client:
            await self._client.__aexit__(*args)

    async def probe_auth(self) -> bool:
        """Return True if server accepts unauthenticated connections."""
        if self.target.startswith("http://") or self.target.startswith("https://"):
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as http:
                    r = await http.get(self.target.rstrip("/"))
                    self.auth_required = r.status_code in (401, 403)
                    return not self.auth_required
            except Exception as e:
                logger.debug("Auth probe error: %s", e)
        # STDIO / unknown: assume no network auth
        return True

    async def get_inventory(self) -> ServerInventory:
        assert self._client, "Client not connected — use as async context manager"

        tools = await self._safe_list_tools()
        resources = await self._safe_list_resources()
        resource_templates = await self._safe_list_resource_templates()
        prompts = await self._safe_list_prompts()

        return ServerInventory(
            target=self.target,
            transport=self.transport,
            auth_required=self.auth_required,
            tools=tools,
            resources=resources,
            resource_templates=resource_templates,
            prompts=prompts,
        )

    async def _safe_list_tools(self) -> list[dict]:
        try:
            raw = await self._client.list_tools()
            return [
                {
                    "name": t.name,
                    "description": getattr(t, "description", "") or "",
                    "inputSchema": getattr(t, "inputSchema", {}) or {},
                }
                for t in raw
            ]
        except Exception as e:
            logger.warning("list_tools failed: %s", e)
            return []

    async def _safe_list_resources(self) -> list[dict]:
        try:
            raw = await self._client.list_resources()
            return [
                {
                    "name": getattr(r, "name", "") or "",
                    "uri": str(getattr(r, "uri", "") or ""),
                    "description": getattr(r, "description", "") or "",
                    "mimeType": getattr(r, "mimeType", "") or "",
                }
                for r in raw
            ]
        except Exception as e:
            logger.warning("list_resources failed: %s", e)
            return []

    async def _safe_list_resource_templates(self) -> list[dict]:
        try:
            raw = await self._client.list_resource_templates()
            return [
                {
                    "name": getattr(t, "name", "") or "",
                    "uriTemplate": getattr(t, "uriTemplate", "") or "",
                    "description": getattr(t, "description", "") or "",
                    "mimeType": getattr(t, "mimeType", "") or "",
                }
                for t in raw
            ]
        except Exception as e:
            logger.warning("list_resource_templates failed: %s", e)
            return []

    async def _safe_list_prompts(self) -> list[dict]:
        try:
            raw = await self._client.list_prompts()
            return [
                {
                    "name": getattr(p, "name", "") or "",
                    "description": getattr(p, "description", "") or "",
                    "arguments": [
                        {
                            "name": getattr(a, "name", ""),
                            "required": getattr(a, "required", False),
                        }
                        for a in (getattr(p, "arguments", []) or [])
                    ],
                }
                for p in raw
            ]
        except Exception as e:
            logger.warning("list_prompts failed: %s", e)
            return []

    async def read_resource(self, uri: str) -> str | None:  # noqa: D102
        try:
            result = await self._client.read_resource(uri)
            return _extract_resource_text(result)
        except Exception as e:
            logger.debug("read_resource(%s) failed: %s", uri, e)
            return None

    async def call_tool(self, name: str, arguments: dict) -> dict:
        """Call a tool and return normalized result. Only used during active testing."""
        try:
            result = await self._client.call_tool(name, arguments)
            content = []
            if hasattr(result, "content"):
                for c in result.content:
                    text = getattr(c, "text", None)
                    if text:
                        content.append(text)
            return {
                "success": True,
                "content": content,
                "is_error": getattr(result, "isError", False),
            }
        except Exception as e:
            return {"success": False, "error": str(e), "content": [], "is_error": True}
