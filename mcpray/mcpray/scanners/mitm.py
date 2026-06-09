"""MCP MITM proxy — intercepts and logs all JSON-RPC traffic between an MCP client and server."""
from __future__ import annotations

import json
import re
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Callable

import httpx

# ── Hop-by-hop headers that must not be forwarded across a proxy boundary. ─────────
_HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
}

# ── Heuristic markers used by get_interesting_findings(). ──────────────────────────
_SENSITIVE_TOOL_MARKERS = (
    "exec", "eval", "system", "shell", "command", "cmd", "spawn", "subprocess",
    "file", "read", "write", "delete", "remove", "unlink", "open",
    "sql", "query", "db", "database",
    "http", "fetch", "request", "url", "curl", "wget", "ssrf",
    "secret", "credential", "password", "token", "key", "env",
)

# Standard, well-known MCP / JSON-RPC method names. Anything outside this set is
# flagged as "unusual" so the operator can eyeball custom verbs.
_KNOWN_METHODS = {
    "initialize", "initialized", "notifications/initialized",
    "ping", "shutdown", "exit",
    "tools/list", "tools/call",
    "resources/list", "resources/read", "resources/templates/list",
    "resources/subscribe", "resources/unsubscribe",
    "prompts/list", "prompts/get",
    "completion/complete", "logging/setLevel",
    "roots/list", "sampling/createMessage",
    "notifications/cancelled", "notifications/progress",
    "notifications/message", "notifications/resources/updated",
    "notifications/resources/list_changed", "notifications/tools/list_changed",
    "notifications/prompts/list_changed", "notifications/roots/list_changed",
}

# A long, mostly-base64-alphabet string with no spaces looks like a credential/blob.
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/=_\-]{40,}$")
# Common token prefixes worth flagging even when shorter than the base64 threshold.
_TOKEN_PREFIX_RE = re.compile(
    r"(?:bearer\s+|eyJ|sk-|ghp_|gho_|github_pat_|xox[baprs]-|AKIA|ASIA|AIza|glpat-)",
    re.IGNORECASE,
)
# Lines that betray a server-side stack trace in an error message / body.
_STACKTRACE_MARKERS = (
    "traceback (most recent call last)",
    'file "', "line ", " in <module>",
    "\tat ", "exception in thread", "caused by:",
    "stack trace", "stacktrace",
)

_LARGE_RESPONSE_BYTES = 100 * 1024  # 100KB


# ── Data model ─────────────────────────────────────────────────────────────────────

@dataclass
class InterceptedRequest:
    timestamp: float
    direction: str          # "client->proxy" or "proxy->server"
    method: str             # JSON-RPC method
    id: int | str | None
    params: dict | None
    raw_body: str

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "direction": self.direction,
            "method": self.method,
            "id": self.id,
            "params": self.params,
            "raw_body": self.raw_body,
        }


@dataclass
class InterceptedResponse:
    timestamp: float
    direction: str          # "server->proxy" or "proxy->client"
    request_id: int | str | None
    result: dict | None
    error: dict | None
    raw_body: str
    latency_ms: float

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "direction": self.direction,
            "request_id": self.request_id,
            "result": self.result,
            "error": self.error,
            "raw_body": self.raw_body,
            "latency_ms": self.latency_ms,
        }


@dataclass
class InterceptedExchange:
    request: InterceptedRequest
    response: InterceptedResponse | None = None
    modified: bool = False
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "request": self.request.to_dict() if self.request else None,
            "response": self.response.to_dict() if self.response else None,
            "modified": self.modified,
            "notes": list(self.notes),
        }


@dataclass
class ProxySession:
    upstream: str           # real MCP server URL
    listen_host: str
    listen_port: int
    exchanges: list[InterceptedExchange] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)

    @property
    def proxy_url(self) -> str:
        return f"http://{self.listen_host}:{self.listen_port}"

    def to_dict(self) -> dict:
        return {
            "upstream": self.upstream,
            "listen_host": self.listen_host,
            "listen_port": self.listen_port,
            "proxy_url": self.proxy_url,
            "started_at": self.started_at,
            "exchange_count": len(self.exchanges),
            "exchanges": [ex.to_dict() for ex in self.exchanges],
        }


# ── Parsing helpers ─────────────────────────────────────────────────────────────────

def _parse_jsonrpc(raw: str) -> dict | None:
    """Best-effort parse of a JSON-RPC object from a raw body. Returns None on failure."""
    raw = (raw or "").strip()
    if not raw:
        return None
    try:
        obj = json.loads(raw)
    except (ValueError, TypeError):
        return None
    if isinstance(obj, dict):
        return obj
    # Batched JSON-RPC arrives as a list; surface the first object so the
    # exchange still records something meaningful.
    if isinstance(obj, list) and obj and isinstance(obj[0], dict):
        return obj[0]
    return None


def _iter_sse_jsonrpc(raw: str):
    """Yield JSON-RPC dicts parsed out of an SSE stream body (``data:`` lines)."""
    for line in raw.splitlines():
        line = line.strip()
        if not line.lower().startswith("data:"):
            continue
        payload = line[5:].strip()
        if not payload or payload == "[DONE]":
            continue
        obj = _parse_jsonrpc(payload)
        if obj is not None:
            yield obj


def _filter_headers(headers: dict[str, str]) -> dict[str, str]:
    """Drop hop-by-hop headers so they are not blindly relayed across the proxy."""
    return {k: v for k, v in headers.items() if k.lower() not in _HOP_BY_HOP}


# ── HTTP handler ─────────────────────────────────────────────────────────────────────

class _MCPProxyHandler(BaseHTTPRequestHandler):
    """HTTP handler that proxies JSON-RPC to upstream MCP server."""

    # Set by MCPMitmProxy before server start:
    upstream_url: str = ""
    session: ProxySession = None
    intercept_callback: Callable[[InterceptedExchange], InterceptedExchange | None] | None = None
    verbose: bool = False
    lock: threading.Lock = threading.Lock()

    # Keep BaseHTTPRequestHandler from advertising the Python version.
    server_version = "mcpray-mitm/1.0"
    protocol_version = "HTTP/1.1"

    # ── logging ────────────────────────────────────────────────────────────────────
    def log_message(self, fmt, *args):  # noqa: D102
        if self.verbose:
            print(f"[mitm] {fmt % args}")

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(f"[mitm] {msg}")

    # ── upstream URL resolution ──────────────────────────────────────────────────────
    def _upstream_for_path(self) -> str:
        """Join the request path onto the upstream base, preserving the query string."""
        base = self.upstream_url.rstrip("/")
        # self.path already includes any query string.
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path or "/"
        # If the upstream URL already carries a path component (e.g. /mcp), and the
        # client targeted the proxy root, prefer the upstream path.
        up = urllib.parse.urlsplit(self.upstream_url)
        if path == "/" and up.path and up.path != "/":
            target = self.upstream_url
        else:
            target = base + path
        if parsed.query:
            sep = "&" if "?" in target else "?"
            target = f"{target}{sep}{parsed.query}"
        return target

    def _client_headers(self) -> dict[str, str]:
        return _filter_headers({k: v for k, v in self.headers.items()})

    # ── append-with-lock ─────────────────────────────────────────────────────────────
    def _record(self, exchange: InterceptedExchange) -> None:
        with self.lock:
            self.session.exchanges.append(exchange)

    # ── GET / SSE ────────────────────────────────────────────────────────────────────
    def do_GET(self):  # noqa: N802
        """Proxy a GET (typically the SSE event channel) and stream events back."""
        target = self._upstream_for_path()
        headers = self._client_headers()
        start = time.time()
        self._vprint(f"GET {self.path} -> {target}")

        try:
            with httpx.Client(timeout=None, follow_redirects=True) as client:
                with client.stream("GET", target, headers=headers) as upstream:
                    content_type = upstream.headers.get("content-type", "")
                    is_sse = "text/event-stream" in content_type.lower()

                    # Mirror status + headers to the client.
                    self.send_response(upstream.status_code)
                    for k, v in upstream.headers.items():
                        if k.lower() in _HOP_BY_HOP:
                            continue
                        self.send_header(k, v)
                    self.end_headers()

                    if not is_sse:
                        # Plain body — relay verbatim, record if it is JSON-RPC.
                        body = b""
                        for chunk in upstream.iter_bytes():
                            body += chunk
                            try:
                                self.wfile.write(chunk)
                                self.wfile.flush()
                            except (BrokenPipeError, ConnectionResetError):
                                return
                        self._record_get_body(body.decode("utf-8", "replace"),
                                              upstream.status_code, start)
                        return

                    # SSE — forward line by line, parsing data: events as we go.
                    sse_buffer = ""
                    for raw_line in upstream.iter_lines():
                        line = raw_line if isinstance(raw_line, str) else raw_line.decode(
                            "utf-8", "replace"
                        )
                        try:
                            self.wfile.write((line + "\n").encode("utf-8"))
                            self.wfile.flush()
                        except (BrokenPipeError, ConnectionResetError):
                            break
                        sse_buffer += line + "\n"
                        # Each SSE event ends on a blank line — flush the buffer then.
                        if line.strip() == "":
                            self._record_sse_events(sse_buffer, start)
                            sse_buffer = ""
                    if sse_buffer.strip():
                        self._record_sse_events(sse_buffer, start)
        except httpx.HTTPError as e:
            self._vprint(f"GET upstream error: {e}")
            try:
                self.send_response(502)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": f"proxy upstream error: {e}"}).encode())
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _record_sse_events(self, sse_buffer: str, start: float) -> None:
        now = time.time()
        for obj in _iter_sse_jsonrpc(sse_buffer):
            method = obj.get("method", "")
            if method:
                # A request/notification arriving over SSE (server-initiated).
                req = InterceptedRequest(
                    timestamp=now,
                    direction="server->proxy",
                    method=method,
                    id=obj.get("id"),
                    params=obj.get("params"),
                    raw_body=json.dumps(obj),
                )
                self._record(InterceptedExchange(request=req))
            else:
                resp = InterceptedResponse(
                    timestamp=now,
                    direction="server->proxy",
                    request_id=obj.get("id"),
                    result=obj.get("result"),
                    error=obj.get("error"),
                    raw_body=json.dumps(obj),
                    latency_ms=(now - start) * 1000.0,
                )
                ex = self._match_pending_response(obj.get("id"), resp)
                if ex is None:
                    self._record(InterceptedExchange(
                        request=InterceptedRequest(
                            timestamp=start, direction="server->proxy",
                            method="(sse-response)", id=obj.get("id"),
                            params=None, raw_body="",
                        ),
                        response=resp,
                    ))

    def _record_get_body(self, body: str, status: int, start: float) -> None:
        obj = _parse_jsonrpc(body)
        if obj is None:
            return
        now = time.time()
        resp = InterceptedResponse(
            timestamp=now,
            direction="server->proxy",
            request_id=obj.get("id"),
            result=obj.get("result"),
            error=obj.get("error"),
            raw_body=body,
            latency_ms=(now - start) * 1000.0,
        )
        self._record(InterceptedExchange(
            request=InterceptedRequest(
                timestamp=start, direction="server->proxy", method="(get)",
                id=obj.get("id"), params=None, raw_body="",
            ),
            response=resp,
        ))

    def _match_pending_response(
        self, req_id, resp: InterceptedResponse
    ) -> InterceptedExchange | None:
        """Attach an SSE-delivered response to the most recent matching open request."""
        if req_id is None:
            return None
        with self.lock:
            for ex in reversed(self.session.exchanges):
                if ex.response is None and ex.request and ex.request.id == req_id:
                    ex.response = resp
                    return ex
        return None

    # ── POST / JSON-RPC ──────────────────────────────────────────────────────────────
    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        raw = body.decode("utf-8", "replace")

        obj = _parse_jsonrpc(raw) or {}
        req = InterceptedRequest(
            timestamp=time.time(),
            direction="client->proxy",
            method=obj.get("method", ""),
            id=obj.get("id"),
            params=obj.get("params"),
            raw_body=raw,
        )
        exchange = InterceptedExchange(request=req)
        self._vprint(f"POST method={req.method!r} id={req.id!r}")

        # Allow an interceptor to inspect / mutate / drop the request.
        if self.intercept_callback is not None:
            try:
                result = self.intercept_callback(exchange)
            except Exception as e:  # noqa: BLE001
                exchange.notes.append(f"interceptor raised: {e}")
                result = exchange
            if result is None:
                # Dropped — respond 403 and still record the (dropped) exchange.
                exchange.notes.append("dropped by interceptor")
                self._record(exchange)
                self._send_json(403, {
                    "jsonrpc": "2.0",
                    "id": req.id,
                    "error": {"code": -32000, "message": "request blocked by mitm proxy"},
                })
                return
            exchange = result

        # If the interceptor mutated params, re-serialize the body to forward.
        forward_body = exchange.request.raw_body.encode("utf-8")
        if exchange.modified:
            rebuilt = _parse_jsonrpc(exchange.request.raw_body)
            if rebuilt is not None and exchange.request.params is not None:
                rebuilt["params"] = exchange.request.params
                forward_body = json.dumps(rebuilt).encode("utf-8")
                exchange.request.raw_body = forward_body.decode("utf-8")

        start = time.time()
        try:
            status, resp_body, resp_headers = self._forward_post(
                forward_body, self._client_headers()
            )
        except httpx.HTTPError as e:
            self._vprint(f"POST upstream error: {e}")
            exchange.notes.append(f"upstream error: {e}")
            self._record(exchange)
            self._send_json(502, {
                "jsonrpc": "2.0",
                "id": req.id,
                "error": {"code": -32001, "message": f"proxy upstream error: {e}"},
            })
            return

        latency_ms = (time.time() - start) * 1000.0
        resp_text = resp_body.decode("utf-8", "replace")
        content_type = resp_headers.get("content-type", "")

        # Parse the JSON-RPC response — from plain JSON or from an SSE body.
        parsed: dict | None = _parse_jsonrpc(resp_text)
        if parsed is None and "text/event-stream" in content_type.lower():
            for ev in _iter_sse_jsonrpc(resp_text):
                # Prefer the event that answers our request id.
                if ev.get("id") == req.id or parsed is None:
                    parsed = ev
                if ev.get("id") == req.id:
                    break

        exchange.response = InterceptedResponse(
            timestamp=time.time(),
            direction="server->proxy",
            request_id=(parsed.get("id") if parsed else req.id),
            result=(parsed.get("result") if parsed else None),
            error=(parsed.get("error") if parsed else None),
            raw_body=resp_text,
            latency_ms=latency_ms,
        )
        self._record(exchange)

        # Relay the upstream response verbatim to the client.
        try:
            self.send_response(status)
            sent_ct = False
            for k, v in resp_headers.items():
                if k.lower() in _HOP_BY_HOP:
                    continue
                if k.lower() == "content-type":
                    sent_ct = True
                self.send_header(k, v)
            if not sent_ct:
                self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _forward_post(
        self, body: bytes, extra_headers: dict
    ) -> tuple[int, bytes, dict]:
        """Forward POST to upstream, return (status_code, response_body, headers)."""
        target = self._upstream_for_path()
        headers = dict(extra_headers)
        headers["Content-Type"] = headers.get("Content-Type", "application/json")
        with httpx.Client(timeout=60.0, follow_redirects=True) as client:
            r = client.post(target, content=body, headers=headers)
            return r.status_code, r.content, dict(r.headers)

    # ── response helper ──────────────────────────────────────────────────────────────
    def _send_json(self, status: int, payload: dict) -> None:
        data = json.dumps(payload).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass


# ── Threaded HTTP server ──────────────────────────────────────────────────────────────

class _ThreadingHTTPServer(HTTPServer):
    """HTTPServer that handles each request in its own daemon thread."""

    daemon_threads = True
    allow_reuse_address = True

    def process_request(self, request, client_address):
        t = threading.Thread(
            target=self._handle_request_thread,
            args=(request, client_address),
            daemon=True,
        )
        t.start()

    def _handle_request_thread(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except Exception:  # noqa: BLE001
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)


# ── Main proxy class ────────────────────────────────────────────────────────────────

class MCPMitmProxy:
    def __init__(
        self,
        upstream: str,
        listen_host: str = "127.0.0.1",
        listen_port: int = 19080,
        verbose: bool = False,
        intercept: Callable[[InterceptedExchange], InterceptedExchange | None] | None = None,
    ):
        self.upstream = upstream
        self.session = ProxySession(
            upstream=upstream, listen_host=listen_host, listen_port=listen_port
        )
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.intercept = intercept
        self.verbose = verbose
        self._lock = threading.Lock()

    # ── lifecycle ────────────────────────────────────────────────────────────────────
    def start(self) -> str:
        """Start proxy in background thread. Returns proxy URL."""
        host = self.session.listen_host
        port = self.session.listen_port

        # Build a fresh handler subclass so per-instance config doesn't leak across
        # proxies sharing the _MCPProxyHandler base.
        proxy = self

        class _BoundHandler(_MCPProxyHandler):
            upstream_url = proxy.upstream
            session = proxy.session
            intercept_callback = proxy.intercept
            verbose = proxy.verbose
            lock = proxy._lock

        self._server = _ThreadingHTTPServer((host, port), _BoundHandler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )
        self._thread.start()
        if self.verbose:
            print(f"[mitm] proxy listening on {self.session.proxy_url} -> {self.upstream}")
        return self.session.proxy_url

    def stop(self):
        """Shutdown proxy server."""
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:  # noqa: BLE001
                pass
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        if self.verbose:
            print("[mitm] proxy stopped")

    # ── access ───────────────────────────────────────────────────────────────────────
    def get_exchanges(self) -> list[InterceptedExchange]:
        with self._lock:
            return list(self.session.exchanges)

    # ── reporting ──────────────────────────────────────────────────────────────────────
    def print_summary(self):
        """Print a Rich table of all intercepted exchanges."""
        exchanges = self.get_exchanges()
        try:
            from rich.console import Console
            from rich.table import Table
            from rich import box
        except Exception:  # noqa: BLE001 — rich unavailable, fall back to plain text
            self._print_summary_plain(exchanges)
            return

        console = Console()
        table = Table(
            title=f"MITM exchanges  {self.session.proxy_url} -> {self.upstream}",
            box=box.ROUNDED, show_lines=False, padding=(0, 1),
        )
        table.add_column("time", style="dim", no_wrap=True)
        table.add_column("method", style="cyan")
        table.add_column("id", justify="right", no_wrap=True)
        table.add_column("params", overflow="fold", max_width=40)
        table.add_column("response", overflow="fold", max_width=40)
        table.add_column("ms", justify="right", no_wrap=True)
        table.add_column("M", justify="center", no_wrap=True)

        for ex in exchanges:
            req = ex.request
            ts = time.strftime("%H:%M:%S", time.localtime(req.timestamp))
            params_summary = self._summarize(req.params)
            resp = ex.response
            if resp is None:
                resp_summary = "[yellow](no response)[/]"
                ms = ""
            elif resp.error is not None:
                resp_summary = f"[red]error: {self._summarize(resp.error)}[/]"
                ms = f"{resp.latency_ms:.0f}"
            else:
                resp_summary = self._summarize(resp.result)
                ms = f"{resp.latency_ms:.0f}"
            table.add_row(
                ts, req.method or "(none)", str(req.id),
                params_summary, resp_summary, ms,
                "[bold magenta]*[/]" if ex.modified else "",
            )
        console.print(table)

    def _print_summary_plain(self, exchanges: list[InterceptedExchange]) -> None:
        print(f"MITM exchanges  {self.session.proxy_url} -> {self.upstream}")
        print(f"{'time':8} {'method':24} {'id':>6} {'ms':>6}  summary")
        for ex in exchanges:
            req = ex.request
            ts = time.strftime("%H:%M:%S", time.localtime(req.timestamp))
            resp = ex.response
            ms = f"{resp.latency_ms:.0f}" if resp else "-"
            if resp is None:
                summary = "(no response)"
            elif resp.error is not None:
                summary = f"error: {self._summarize(resp.error)}"
            else:
                summary = self._summarize(resp.result)
            flag = " *" if ex.modified else ""
            print(f"{ts:8} {(req.method or '(none)'):24} {str(req.id):>6} "
                  f"{ms:>6}  {summary}{flag}")

    @staticmethod
    def _summarize(obj, limit: int = 120) -> str:
        if obj is None:
            return ""
        try:
            s = json.dumps(obj, default=str)
        except Exception:  # noqa: BLE001
            s = str(obj)
        if len(s) > limit:
            s = s[: limit - 3] + "..."
        return s

    def save_session(self, path: str):
        """Save full session as JSON to path."""
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.session.to_dict(), f, indent=2, default=str)
        if self.verbose:
            print(f"[mitm] session saved to {path}")

    # ── analysis ───────────────────────────────────────────────────────────────────────
    def get_interesting_findings(self) -> list[str]:
        """Analyze captured traffic for security findings.

        - Large response sizes (>100KB) → potential data exfil or context flooding
        - Tool calls to sensitive-sounding tools (exec, system, file, etc.)
        - Credential-like values in params (base64, long strings)
        - Error responses with stack traces (info leak)
        - Unusual method names
        """
        findings: list[str] = []
        seen: set[str] = set()

        def add(msg: str) -> None:
            if msg not in seen:
                seen.add(msg)
                findings.append(msg)

        for ex in self.get_exchanges():
            req = ex.request
            resp = ex.response
            method = (req.method or "").strip()

            # 1. Large responses.
            if resp is not None and resp.raw_body:
                size = len(resp.raw_body.encode("utf-8", "replace"))
                if size > _LARGE_RESPONSE_BYTES:
                    add(f"Large response ({size // 1024}KB) for method "
                        f"'{method or '(none)'}' id={req.id} — possible data exfil "
                        f"or context flooding")

            # 2. Sensitive tool calls.
            if method == "tools/call":
                tool_name = ""
                if isinstance(req.params, dict):
                    tool_name = str(req.params.get("name", ""))
                tl = tool_name.lower()
                hit = next((m for m in _SENSITIVE_TOOL_MARKERS if m in tl), None)
                if hit:
                    add(f"Sensitive tool invoked: '{tool_name}' (matched '{hit}') "
                        f"id={req.id}")

            # 3. Credential-like values in params.
            for path_, val in self._iter_param_strings(req.params):
                if _TOKEN_PREFIX_RE.search(val):
                    add(f"Credential-like value (token prefix) in {method or '(req)'} "
                        f"param '{path_}': {self._redact(val)}")
                elif len(val) >= 40 and _BASE64_RE.match(val):
                    add(f"Credential-like value (long base64/blob) in "
                        f"{method or '(req)'} param '{path_}': {self._redact(val)}")

            # 4. Error responses with stack traces.
            if resp is not None:
                blob = resp.raw_body or ""
                if resp.error is not None:
                    blob += " " + json.dumps(resp.error, default=str)
                low = blob.lower()
                if any(m in low for m in _STACKTRACE_MARKERS):
                    add(f"Error/stack-trace leak in response to '{method or '(none)'}' "
                        f"id={req.id} — server internals exposed")

            # 5. Unusual method names.
            if method and method not in _KNOWN_METHODS:
                add(f"Unusual JSON-RPC method observed: '{method}' id={req.id}")

        return findings

    @classmethod
    def _iter_param_strings(cls, obj, prefix: str = ""):
        """Recursively yield (path, str_value) pairs from a params structure."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                yield from cls._iter_param_strings(v, f"{prefix}.{k}" if prefix else str(k))
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                yield from cls._iter_param_strings(v, f"{prefix}[{i}]")
        elif isinstance(obj, str):
            yield prefix or "(value)", obj

    @staticmethod
    def _redact(val: str) -> str:
        v = val.strip()
        if len(v) <= 16:
            return v
        return f"{v[:8]}...{v[-4:]} ({len(v)} chars)"

    # ── context manager ──────────────────────────────────────────────────────────────
    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()


# ── Interceptor factories ────────────────────────────────────────────────────────────

def create_logging_interceptor(log_file: str) -> Callable[[InterceptedExchange], InterceptedExchange]:
    """Return an interceptor that appends every exchange's request to a JSONL file.

    The interceptor never drops or mutates requests; it is purely observational.
    Each line is a JSON object describing the intercepted request at decision time.
    """
    file_lock = threading.Lock()

    def _interceptor(exchange: InterceptedExchange) -> InterceptedExchange:
        record = {
            "logged_at": time.time(),
            "request": exchange.request.to_dict() if exchange.request else None,
            "modified": exchange.modified,
            "notes": list(exchange.notes),
        }
        line = json.dumps(record, default=str)
        with file_lock:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        exchange.notes.append(f"logged to {log_file}")
        return exchange

    return _interceptor


def create_tamper_interceptor(
    tool_name: str, param_name: str, replacement: str
) -> Callable[[InterceptedExchange], InterceptedExchange]:
    """Return an interceptor that rewrites one argument of a specific tool call.

    For ``tools/call`` requests where ``params.name == tool_name``, the value of
    ``params.arguments[param_name]`` is replaced with ``replacement``. The exchange
    is marked ``modified`` and a note is recorded. All other traffic passes through
    unchanged.
    """
    def _interceptor(exchange: InterceptedExchange) -> InterceptedExchange:
        req = exchange.request
        if req.method != "tools/call" or not isinstance(req.params, dict):
            return exchange
        if str(req.params.get("name", "")) != tool_name:
            return exchange

        args = req.params.get("arguments")
        if not isinstance(args, dict) or param_name not in args:
            exchange.notes.append(
                f"tamper: tool '{tool_name}' matched but param '{param_name}' absent"
            )
            return exchange

        original = args[param_name]
        args[param_name] = replacement
        exchange.modified = True
        exchange.notes.append(
            f"tamper: {tool_name}.{param_name} {original!r} -> {replacement!r}"
        )
        return exchange

    return _interceptor


__all__ = [
    "InterceptedRequest",
    "InterceptedResponse",
    "InterceptedExchange",
    "ProxySession",
    "MCPMitmProxy",
    "create_logging_interceptor",
    "create_tamper_interceptor",
]
