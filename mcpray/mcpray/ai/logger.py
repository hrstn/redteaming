from __future__ import annotations

# ─── Security note (credential exposure audit) ─────────────────────────────────
# This logger writes session data to mcpray_session_*.jsonl files. Those files
# can end up storing data extracted from target systems (SQL dumps, file reads,
# tool results, cloud metadata), which may contain passwords, API keys and other
# credentials in cleartext.
#
# To avoid persisting sensitive data, every event is passed through
# sanitize_for_log() before being written/buffered:
#   - Long string values (HTTP response bodies, read_resource contents, tool
#     call results) are truncated to MAX_VALUE_LEN chars with a
#     "[TRUNCATED - may contain sensitive data]" marker.
#   - HTTP header values for sensitive headers (Authorization, Cookie,
#     X-API-Key, X-Auth-Token, …) are replaced with "[REDACTED]".
# The original callers in this codebase mostly log only sizes/counts/key-names,
# but sanitize_for_log() is applied centrally in log_event() so that any field
# carrying a body / header / result is sanitized regardless of the caller.
# ───────────────────────────────────────────────────────────────────────────────

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_log = logging.getLogger("mcpray.ai.logger")
_session_events: list[dict] = []
_log_path: Path | None = None

# Maximum length for any logged string value before truncation.
MAX_VALUE_LEN = 500
_TRUNCATION_MARKER = " …[TRUNCATED - may contain sensitive data]"

# Header names whose values must never be written to the log (case-insensitive).
_SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
}
_REDACTED = "[REDACTED]"

# Keys that conventionally carry sensitive/voluminous payloads and should be
# treated as header containers when their value is a dict.
_HEADER_KEYS = {"headers", "request_headers", "response_headers"}


def _redact_headers(headers: dict) -> dict:
    redacted: dict[str, Any] = {}
    for k, v in headers.items():
        if isinstance(k, str) and k.lower() in _SENSITIVE_HEADERS:
            redacted[k] = _REDACTED
        else:
            redacted[k] = _sanitize_value(v)
    return redacted


def _truncate(s: str) -> str:
    if len(s) > MAX_VALUE_LEN:
        return s[:MAX_VALUE_LEN] + _TRUNCATION_MARKER
    return s


def _sanitize_value(value: Any, key: str | None = None) -> Any:
    # Header containers get key-based redaction.
    if isinstance(value, dict):
        if key is not None and key.lower() in _HEADER_KEYS:
            return _redact_headers(value)
        return {k: _sanitize_value(v, key=k) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize_value(v) for v in value]
    if isinstance(value, str):
        # A bare value under a sensitive header key (e.g. {"Authorization": "..."}).
        if key is not None and key.lower() in _SENSITIVE_HEADERS:
            return _REDACTED
        return _truncate(value)
    return value


def sanitize_for_log(data: dict) -> dict:
    """Return a copy of ``data`` safe to persist to the session log.

    Applies two rules recursively:
      * Truncate any string longer than ``MAX_VALUE_LEN`` (HTTP response bodies,
        read_resource contents, tool-call results) and append a marker.
      * Redact the value of sensitive HTTP headers (Authorization, Cookie,
        X-API-Key, X-Auth-Token, …) whether passed as a dict of headers or as a
        direct key/value pair.
    """
    return {k: _sanitize_value(v, key=k) for k, v in data.items()}


def init_session(output_dir: str = ".") -> Path:
    global _log_path
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    _log_path = Path(output_dir) / f"mcpray_session_{ts}.jsonl"
    log_event("session_start", output=str(_log_path))
    return _log_path


def log_event(event: str, **kwargs: Any) -> None:
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        **{k: v for k, v in kwargs.items() if v is not None},
    }
    entry = sanitize_for_log(entry)
    _session_events.append(entry)
    if _log_path:
        try:
            with _log_path.open("a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            _log.debug("Log write failed: %s", e)


def log_ai_request(function: str, model: str, finding_id: str | None = None, **kw: Any) -> None:
    log_event("ai_request", function=function, model=model, finding_id=finding_id, **kw)


def log_ai_response(
    function: str, model: str, duration_ms: int,
    confidence: float | None = None, finding_id: str | None = None, **kw: Any
) -> None:
    log_event("ai_response", function=function, model=model,
              duration_ms=duration_ms, confidence=confidence, finding_id=finding_id, **kw)


def log_repl_command(command: str) -> None:
    log_event("repl_command", command=command)


def log_tool_call(tool: str, args: dict, dry_run: bool, confirmed: bool = False) -> None:
    log_event("tool_call", tool=tool, dry_run=dry_run, confirmed=confirmed,
              arg_keys=list(args.keys()))


def log_payload_generated(finding_id: str, count: int, types: list[str]) -> None:
    log_event("payload_generated", finding_id=finding_id, count=count, types=types)


def get_all_events() -> list[dict]:
    return list(_session_events)


def export_log(path: str) -> None:
    with open(path, "w") as f:
        for e in _session_events:
            f.write(json.dumps(e) + "\n")
