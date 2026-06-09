"""MCP protocol fuzzer — sends malformed JSON-RPC messages to find parser bugs, crashes, and info leaks."""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger("mcpray.fuzzer")

# Patterns that strongly indicate an information leak in a response body.
_STACK_TRACE_RE = re.compile(
    r"Traceback \(most recent call last\)|"
    r"\bat [\w.$]+\([\w.]+:\d+\)|"           # Java/JS stack frame
    r"\bFile \"[^\"]+\", line \d+|"          # Python frame
    r"\bgoroutine \d+ \[",                   # Go panic
    re.IGNORECASE,
)
_FILE_PATH_RE = re.compile(
    r"(?:/(?:usr|home|var|etc|opt|root|tmp|app|srv)/[\w./-]+)|"
    r"(?:[A-Za-z]:\\\\?[\w\\.-]+)",
)
_INTERNAL_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"127\.0\.0\.1)\b",
)
_ISE_DETAIL_RE = re.compile(r"Internal Server Error.{1,}", re.IGNORECASE | re.DOTALL)


@dataclass
class FuzzCase:
    case_id: str
    category: str       # "malformed_json", "missing_field", "wrong_type", "overflow",
                        # "unicode", "null_byte", "method_confusion", "extra_fields"
    description: str
    payload: dict | str  # the JSON-RPC payload sent


@dataclass
class FuzzFinding:
    case_id: str
    category: str
    payload_summary: str      # brief description of what was sent
    status_code: int
    response_snippet: str     # first 300 chars
    anomaly_type: str         # "crash", "info_leak", "unexpected_200", "stack_trace",
                              # "server_error", "hang", "schema_disclosure"
    severity: str             # "CRITICAL","HIGH","MEDIUM","LOW"


@dataclass
class FuzzResult:
    target: str
    total_cases: int = 0
    findings: list[FuzzFinding] = field(default_factory=list)
    error_rate: float = 0.0
    crash_detected: bool = False
    info_leaks: list[str] = field(default_factory=list)


class ProtocolFuzzer:
    """Sends raw malformed JSON-RPC payloads to an MCP HTTP endpoint."""

    _CONCURRENCY = 10
    _HANG_THRESHOLD_MS = 5000.0

    def __init__(self, target: str, timeout: int = 10):
        self.target = target
        self.timeout = timeout

    # ── Fuzz case generation ─────────────────────────────────────────────────────

    def _build_fuzz_cases(self) -> list[FuzzCase]:
        cases: list[FuzzCase] = []
        n = 0

        def add(category: str, description: str, payload: dict | str) -> None:
            nonlocal n
            n += 1
            cases.append(
                FuzzCase(
                    case_id=f"FUZZ-{n:03d}",
                    category=category,
                    description=description,
                    payload=payload,
                )
            )

        # 1. malformed_json
        add("malformed_json", "Not JSON at all", "this is not json at all")
        add("malformed_json", "Truncated JSON object", '{"jsonrpc": "2.0", "method": "tools/list"')
        add("malformed_json", "Trailing garbage after valid JSON", '{"jsonrpc":"2.0","id":1,"method":"tools/list"} GARBAGE')
        add("malformed_json", "Empty body", "")
        add("malformed_json", "Unbalanced brackets", '{"a":[1,2,3}}')

        # 2. missing_field
        add("missing_field", "Missing jsonrpc field", {"id": 1, "method": "tools/list", "params": {}})
        add("missing_field", "Missing id field", {"jsonrpc": "2.0", "method": "tools/list", "params": {}})
        add("missing_field", "Missing method field", {"jsonrpc": "2.0", "id": 1, "params": {}})
        add("missing_field", "Missing params field", {"jsonrpc": "2.0", "id": 1, "method": "tools/call"})
        add("missing_field", "Empty object", {})

        # 3. wrong_type
        add("wrong_type", "id as string", {"jsonrpc": "2.0", "id": "not-an-int", "method": "tools/list", "params": {}})
        add("wrong_type", "method as int", {"jsonrpc": "2.0", "id": 1, "method": 12345, "params": {}})
        add("wrong_type", "params as string", {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": "should-be-object"})
        add("wrong_type", "jsonrpc as number", {"jsonrpc": 2.0, "id": 1, "method": "tools/list", "params": {}})
        add("wrong_type", "params as array", {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": [1, 2, 3]})

        # 4. overflow
        big_string = "A" * (10 * 1024 * 1024)  # 10MB
        add("overflow", "10MB string value", {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"x": big_string}})

        nested: dict = {"v": 1}
        for _ in range(1000):
            nested = {"n": nested}
        add("overflow", "Deeply nested object (depth 1000)", {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": nested})

        add("overflow", "Large array (10k elements)", {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"arr": list(range(10000))}})
        add("overflow", "Large integer (2^63)", {"jsonrpc": "2.0", "id": 2 ** 63, "method": "tools/list", "params": {}})

        # 5. unicode / null_byte
        add("null_byte", "Null byte inside string", {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"x": "before\x00after"}})
        add("unicode", "Surrogate-pair / 4-byte char in param", {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"x": "\U00010000 plane-1 char"}})
        add("unicode", "RTL override char in param", {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"x": "abc‮edcba"}})
        add("unicode", "4-byte emoji in method name", {"jsonrpc": "2.0", "id": 1, "method": "tools/\U0001F600list", "params": {}})

        # 6. method_confusion
        add("method_confusion", "Unknown method 'hack'", {"jsonrpc": "2.0", "id": 1, "method": "hack", "params": {}})
        add("method_confusion", "Unknown method 'eval'", {"jsonrpc": "2.0", "id": 1, "method": "eval", "params": {"code": "1+1"}})
        add("method_confusion", "Unknown method 'admin/shutdown'", {"jsonrpc": "2.0", "id": 1, "method": "admin/shutdown", "params": {}})
        add("method_confusion", "Valid method, wrong params shape", {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"unexpected": True}})
        add("method_confusion", "Case-variation of valid method", {"jsonrpc": "2.0", "id": 1, "method": "Tools/List", "params": {}})

        # 7. extra_fields
        add("extra_fields", "Extra top-level field", {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}, "evil": "payload"})
        add("extra_fields", "Extra field inside params", {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"__proto__": {"polluted": True}}})
        add("extra_fields", "Extra nested unknown field", {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "x", "arguments": {"a": 1}, "meta": {"injected": {"deep": True}}}})

        # 8. batch_requests
        add("method_confusion", "Batch request (array of requests)", [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "resources/list", "params": {}},
            {"jsonrpc": "2.0", "id": 3, "method": "prompts/list", "params": {}},
        ])
        add("method_confusion", "Empty batch (empty array)", [])

        # 9. negative_id
        add("wrong_type", "id = -1", {"jsonrpc": "2.0", "id": -1, "method": "tools/list", "params": {}})
        add("wrong_type", "id = 0", {"jsonrpc": "2.0", "id": 0, "method": "tools/list", "params": {}})
        add("wrong_type", "id = null", {"jsonrpc": "2.0", "id": None, "method": "tools/list", "params": {}})
        add("wrong_type", "id = []", {"jsonrpc": "2.0", "id": [], "method": "tools/list", "params": {}})

        return cases

    # ── Transport ────────────────────────────────────────────────────────────────

    async def _send_raw(
        self, client: httpx.AsyncClient, payload: dict | list | str | bytes
    ) -> tuple[int, str, float]:
        """POST to target. Return (status_code, response_text[:500], latency_ms)."""
        headers = {"Accept": "application/json, text/event-stream"}
        if isinstance(payload, (dict, list)):
            headers["Content-Type"] = "application/json"
            content: bytes = json.dumps(payload).encode("utf-8")
        elif isinstance(payload, str):
            headers["Content-Type"] = "application/json"
            content = payload.encode("utf-8", errors="surrogatepass")
        else:
            headers["Content-Type"] = "application/octet-stream"
            content = payload

        start = time.perf_counter()
        try:
            resp = await client.post(self.target, content=content, headers=headers)
            latency = (time.perf_counter() - start) * 1000.0
            return resp.status_code, resp.text[:500], latency
        except httpx.TimeoutException:
            latency = (time.perf_counter() - start) * 1000.0
            return 0, "<timeout>", latency
        except httpx.HTTPError as e:  # noqa: BLE001
            latency = (time.perf_counter() - start) * 1000.0
            return 0, f"<transport error: {e}>", latency

    # ── Classification ───────────────────────────────────────────────────────────

    def _classify_response(
        self, case: FuzzCase, status: int, body: str, latency: float
    ) -> FuzzFinding | None:
        snippet = body[:300]
        summary = case.description

        def finding(anomaly: str, severity: str) -> FuzzFinding:
            return FuzzFinding(
                case_id=case.case_id,
                category=case.category,
                payload_summary=summary,
                status_code=status,
                response_snippet=snippet,
                anomaly_type=anomaly,
                severity=severity,
            )

        # Transport timeout → potential hang / DoS.
        if status == 0 and "<timeout>" in body:
            return finding("hang", "MEDIUM")

        # Transport-level error (connection dropped) on a payload the server should
        # gracefully reject → likely a crash.
        if status == 0:
            return finding("crash", "HIGH")

        # Stack traces / tracebacks → info leak.
        if _STACK_TRACE_RE.search(body):
            return finding("stack_trace", "HIGH")

        # File paths or internal IPs leaking in the body → info leak.
        if _FILE_PATH_RE.search(body) or _INTERNAL_IP_RE.search(body):
            return finding("info_leak", "HIGH")

        # "Internal Server Error" with extra detail → info leak.
        if "internal server error" in body.lower() and len(body.strip()) > len("internal server error") + 4:
            return finding("info_leak", "HIGH")

        # Server error 5xx → server_error.
        if 500 <= status < 600:
            return finding("server_error", "MEDIUM")

        # Slow response on a small payload → hang.
        if latency > self._HANG_THRESHOLD_MS and case.category != "overflow":
            return finding("hang", "MEDIUM")

        # Unexpected 200 on obviously broken input → low-severity anomaly.
        if status == 200 and case.category in ("malformed_json", "missing_field", "wrong_type"):
            return finding("unexpected_200", "LOW")

        # Schema disclosure: broken request that still echoes full tool/input schema.
        if status == 200 and "inputSchema" in body and case.category in ("method_confusion", "extra_fields"):
            return finding("schema_disclosure", "LOW")

        # Expected error responses (400, structured jsonrpc error) → not a finding.
        return None

    # ── Orchestration ────────────────────────────────────────────────────────────

    async def run(self, max_cases: int | None = None) -> FuzzResult:
        cases = self._build_fuzz_cases()
        if max_cases is not None:
            cases = cases[:max_cases]

        result = FuzzResult(target=self.target, total_cases=len(cases))
        sem = asyncio.Semaphore(self._CONCURRENCY)
        error_count = 0

        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:

            async def worker(case: FuzzCase) -> tuple[FuzzFinding | None, bool]:
                async with sem:
                    status, body, latency = await self._send_raw(client, case.payload)
                is_error = status == 0 or status >= 400
                finding = self._classify_response(case, status, body, latency)
                return finding, is_error

            outcomes = await asyncio.gather(*(worker(c) for c in cases))

        for finding, is_error in outcomes:
            if is_error:
                error_count += 1
            if finding is None:
                continue
            result.findings.append(finding)
            if finding.anomaly_type == "crash":
                result.crash_detected = True
            if finding.anomaly_type in ("info_leak", "stack_trace", "schema_disclosure"):
                result.info_leaks.append(f"{finding.case_id}: {finding.payload_summary}")

        result.error_rate = (error_count / len(cases)) if cases else 0.0
        return result
