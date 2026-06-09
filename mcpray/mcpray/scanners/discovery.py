"""MCP server discovery — port scan, endpoint probe, and fingerprinting."""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from dataclasses import dataclass, field
from typing import AsyncIterator

import httpx

# ── Constants ──────────────────────────────────────────────────────────────────

_DEFAULT_PORTS = [80, 443, 3000, 3001, 4000, 5000, 5001, 7000,
                  8000, 8001, 8008, 8080, 8081, 8443, 8888, 9000, 9001, 9090]

_MCP_PATHS = [
    "/mcp",
    "/sse",
    "/mcp/sse",
    "/api/mcp",
    "/v1/mcp",
    "/mcp/v1",
    "/",
    "/events",
    "/stream",
    "/rpc",
    "/jsonrpc",
    "/mcp/jsonrpc",
]

_MCP_INIT_PAYLOAD = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "mcpray-discovery", "version": "1.0.0"},
    },
}

_FRAMEWORK_SIGS = {
    "fastmcp":         ["fastmcp", "FastMCP"],
    "mcp-python-sdk":  ["mcp", "ModelContextProtocol"],
    "mcp-node-sdk":    ["@modelcontextprotocol"],
    "mcp-go":          ["mcp-go"],
    "mcp-rs":          ["mcp-rs", "rmcp"],
}


# ── Data models ────────────────────────────────────────────────────────────────

@dataclass
class DiscoveredServer:
    host: str
    port: int
    path: str
    url: str
    scheme: str = "http"
    reachable: bool = False
    auth_required: bool = False
    tool_count: int = 0
    resource_count: int = 0
    template_count: int = 0
    prompt_count: int = 0
    server_name: str = ""
    server_version: str = ""
    framework: str = ""
    response_time_ms: float = 0.0
    response_headers: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def capability_summary(self) -> str:
        parts = []
        if self.tool_count:
            parts.append(f"T:{self.tool_count}")
        if self.resource_count or self.template_count:
            parts.append(f"R:{self.resource_count}+{self.template_count}tmpl")
        if self.prompt_count:
            parts.append(f"P:{self.prompt_count}")
        return "  ".join(parts) if parts else "—"

    @property
    def risk_flags(self) -> list[str]:
        flags = []
        if not self.auth_required:
            flags.append("ANON")
        if self.tool_count > 0:
            flags.append("TOOLS")
        return flags


@dataclass
class DiscoveryResult:
    target: str
    hosts_scanned: int = 0
    ports_probed: int = 0
    endpoints_tried: int = 0
    servers: list[DiscoveredServer] = field(default_factory=list)
    scan_duration_s: float = 0.0

    @property
    def reachable_servers(self) -> list[DiscoveredServer]:
        return [s for s in self.servers if s.reachable]


# ── Port scanner ───────────────────────────────────────────────────────────────

async def _tcp_open(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _scan_ports(
    host: str, ports: list[int], timeout: float = 1.5, concurrency: int = 200
) -> list[int]:
    sem = asyncio.Semaphore(concurrency)

    async def _probe(port: int) -> tuple[int, bool]:
        async with sem:
            return port, await _tcp_open(host, port, timeout)

    results = await asyncio.gather(*[_probe(p) for p in ports])
    return [port for port, open_ in results if open_]


# ── HTTP probe ─────────────────────────────────────────────────────────────────

async def _http_probe(
    client: httpx.AsyncClient,
    url: str,
) -> tuple[bool, int, dict[str, str], float, bytes]:
    """Return (success, status_code, headers, latency_ms, body_prefix)."""
    try:
        t0 = time.monotonic()
        r = await client.get(url, follow_redirects=True)
        latency = (time.monotonic() - t0) * 1000
        body = r.content[:4096]
        return True, r.status_code, dict(r.headers), latency, body
    except Exception:
        return False, 0, {}, 0.0, b""


async def _mcp_init_probe(
    client: httpx.AsyncClient, url: str
) -> tuple[bool, dict]:
    """POST JSON-RPC initialize to url. Return (success, result_dict)."""
    try:
        r = await client.post(url, json=_MCP_INIT_PAYLOAD, timeout=5)
        if r.status_code in (200, 202):
            try:
                return True, r.json()
            except Exception:
                pass
        return False, {}
    except Exception:
        return False, {}


def _fingerprint_framework(headers: dict[str, str], body: bytes) -> str:
    text = body.decode("utf-8", errors="replace")
    all_text = " ".join(headers.values()) + " " + text
    for fw, sigs in _FRAMEWORK_SIGS.items():
        if any(s.lower() in all_text.lower() for s in sigs):
            return fw
    return ""


def _is_mcp_endpoint(status: int, headers: dict[str, str], body: bytes) -> bool:
    if status == 0:
        return False
    body_text = body.decode("utf-8", errors="replace").lower()
    # SSE endpoint
    ct = headers.get("content-type", "")
    if "text/event-stream" in ct:
        return True
    # JSON-RPC response
    if "jsonrpc" in body_text or '"result"' in body_text:
        return True
    # Explicit MCP headers
    if "mcp" in ct.lower() or "mcp" in headers.get("server", "").lower():
        return True
    # 405 on GET (POST-only JSON-RPC endpoint) is a strong signal
    if status == 405:
        return True
    return False


# ── MCP capability enum via fastmcp ───────────────────────────────────────────

async def _enum_capabilities(url: str, timeout: int = 10) -> tuple[int, int, int, int, bool]:
    """Return (tools, resources, templates, prompts, auth_required)."""
    try:
        from ..client import MCPClient
        async with MCPClient(url, timeout=timeout) as mc:
            auth_ok = await mc.probe_auth()
            inv = await mc.get_inventory()
            return (
                len(inv.tools),
                len(inv.resources),
                len(inv.resource_templates),
                len(inv.prompts),
                not auth_ok,
            )
    except Exception:
        return 0, 0, 0, 0, False


# ── Host expansion ─────────────────────────────────────────────────────────────

def _expand_target(target: str) -> list[str]:
    """Accept IP, hostname, or CIDR → list of host strings."""
    target = target.strip()
    # Strip scheme if present
    for scheme in ("http://", "https://"):
        if target.startswith(scheme):
            target = target[len(scheme):].split("/")[0].split(":")[0]
            break
    try:
        net = ipaddress.ip_network(target, strict=False)
        return [str(h) for h in net.hosts()] if net.num_addresses > 1 else [str(net.network_address)]
    except ValueError:
        # hostname or plain IP
        return [target]


def _parse_port_range(port_range: str) -> list[int]:
    ports: list[int] = []
    for part in port_range.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.extend(range(int(lo), int(hi) + 1))
        else:
            ports.append(int(part))
    return list(dict.fromkeys(ports))  # deduplicate, preserve order


# ── Main discovery engine ──────────────────────────────────────────────────────

async def discover(
    target: str,
    ports: list[int] | None = None,
    paths: list[str] | None = None,
    timeout: int = 5,
    port_concurrency: int = 200,
    enum_capabilities: bool = True,
    schemes: list[str] | None = None,
    on_progress: "asyncio.Queue | None" = None,
) -> DiscoveryResult:
    t_start = time.monotonic()
    result = DiscoveryResult(target=target)

    ports = ports or _DEFAULT_PORTS
    paths = paths or _MCP_PATHS
    schemes = schemes or ["http", "https"]

    hosts = _expand_target(target)
    result.hosts_scanned = len(hosts)

    async with httpx.AsyncClient(
        verify=False, timeout=timeout,
        headers={"User-Agent": "mcpray-discovery/1.0"},
    ) as http:
        for host in hosts:
            # ── 1. TCP port scan ──────────────────────────────────────────────
            if on_progress:
                await on_progress.put(("port_scan", host))

            open_ports = await _scan_ports(host, ports, timeout=1.5,
                                           concurrency=port_concurrency)
            result.ports_probed += len(ports)

            if not open_ports:
                continue

            # ── 2. HTTP probe on open ports ───────────────────────────────────
            for port in open_ports:
                probe_schemes = ["https"] if port in (443, 8443) else schemes
                for scheme in probe_schemes:
                    for path in paths:
                        url = f"{scheme}://{host}:{port}{path}"
                        result.endpoints_tried += 1

                        ok, status, headers, latency, body = await _http_probe(http, url)
                        if not ok:
                            continue

                        if not _is_mcp_endpoint(status, headers, body):
                            continue

                        srv = DiscoveredServer(
                            host=host,
                            port=port,
                            path=path,
                            url=url,
                            scheme=scheme,
                            reachable=True,
                            response_time_ms=round(latency, 1),
                            response_headers=headers,
                            framework=_fingerprint_framework(headers, body),
                            auth_required=status in (401, 403),
                            server_name=headers.get("server", ""),
                        )

                        if on_progress:
                            await on_progress.put(("found", url))

                        # ── 3. Capability enum ────────────────────────────────
                        if enum_capabilities and status not in (401, 403):
                            t, r_, tmpl, p, auth_req = await _enum_capabilities(
                                url, timeout=timeout
                            )
                            srv.tool_count = t
                            srv.resource_count = r_
                            srv.template_count = tmpl
                            srv.prompt_count = p
                            if auth_req:
                                srv.auth_required = True

                        # ── 4. Fingerprint from init payload ─────────────────
                        if status != 405:  # skip if GET already worked
                            init_ok, init_data = await _mcp_init_probe(http, url)
                            if init_ok:
                                result_data = init_data.get("result", {})
                                si = result_data.get("serverInfo", {})
                                srv.server_name = si.get("name", srv.server_name)
                                srv.server_version = si.get("version", "")

                        result.servers.append(srv)
                        # Found MCP on this port+scheme — try remaining paths
                        # but don't re-probe the same port with both schemes
                        break

    result.scan_duration_s = round(time.monotonic() - t_start, 2)
    return result
