"""Unified AI client — OpenAI, Ollama, and hybrid routing.

No hard dep on the `openai` package; uses httpx directly so both providers
work with the same transport and the package stays optional.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Literal

import httpx

from ..findings import Finding, ScanResult
from .functions import (
    OPENAI_TOOLS,
    build_analyze_finding_prompt,
    build_attack_surface_prompt,
    build_suggest_payloads_prompt,
    get_system_prompt,
)
from .logger import log_ai_request, log_ai_response

_log = logging.getLogger("mcpray.ai.client")

AIMode = Literal["openai", "ollama", "hybrid"]


class AIError(Exception):
    pass


class AIClient:
    """Unified AI client supporting OpenAI-compatible, Ollama, and hybrid modes."""

    def __init__(
        self,
        mode: AIMode = "openai",
        openai_api_key: str | None = None,
        openai_base_url: str = "https://api.openai.com/v1",
        openai_model: str = "gpt-4o-mini",
        ollama_base_url: str = "http://localhost:11434",
        ollama_model: str = "llama3.2",
        timeout: int = 90,
        hybrid_openai_weight: float = 0.6,
    ):
        self.mode = mode
        self.openai_api_key = openai_api_key
        self.openai_base_url = openai_base_url.rstrip("/")
        self.openai_model = openai_model
        self.ollama_base_url = ollama_base_url.rstrip("/")
        self.ollama_model = ollama_model
        self.timeout = timeout
        self._hybrid_weight = hybrid_openai_weight  # OpenAI weight in consensus

    # ─── Public interface ────────────────────────────────────────────────────

    async def analyze_finding(
        self, finding: Finding, context: dict | None = None
    ) -> dict:
        prompt = build_analyze_finding_prompt(finding, context)
        return await self.call("analyze_finding", {"prompt": prompt, "finding": finding})

    async def suggest_payloads(self, finding: Finding) -> dict:
        prompt = build_suggest_payloads_prompt(finding)
        return await self.call("suggest_payloads", {"prompt": prompt, "finding": finding})

    async def attack_surface_summary(self, result: ScanResult) -> dict:
        prompt = build_attack_surface_prompt(result)
        return await self.call("attack_surface_summary", {"prompt": prompt})

    async def call(self, function_name: str, payload: dict) -> dict:
        if self.mode == "openai":
            return await self._openai_call(function_name, payload)
        if self.mode == "ollama":
            return await self._ollama_call(function_name, payload)
        if self.mode == "hybrid":
            return await self._hybrid_call(function_name, payload)
        raise AIError(f"Unknown AI mode: {self.mode!r}")

    # ─── OpenAI / OpenAI-compatible ─────────────────────────────────────────

    async def _openai_call(self, function_name: str, payload: dict) -> dict:
        if not self.openai_api_key:
            raise AIError("OpenAI API key not configured (set OPENAI_API_KEY or pass --ai-key)")

        system_prompt = get_system_prompt(function_name)
        user_message = payload.get("prompt", "")
        tool_def = next((t for t in OPENAI_TOOLS if t["function"]["name"] == function_name), None)

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ]

        body: dict[str, Any] = {
            "model": self.openai_model,
            "messages": messages,
            "temperature": 0.1,
        }

        if tool_def:
            # Force function calling for structured output
            body["tools"] = [tool_def]
            body["tool_choice"] = {"type": "function", "function": {"name": function_name}}

        model_label = f"{self.openai_model}@openai"
        log_ai_request(function_name, model_label,
                       finding_id=getattr(payload.get("finding"), "id", None))
        t0 = time.monotonic()

        async with httpx.AsyncClient(timeout=self.timeout) as http:
            try:
                resp = await http.post(
                    f"{self.openai_base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.openai_api_key}",
                        "Content-Type": "application/json",
                    },
                    json=body,
                )
                resp.raise_for_status()
            except httpx.HTTPStatusError as e:
                raise AIError(f"OpenAI API error {e.response.status_code}: {e.response.text[:300]}") from e
            except httpx.RequestError as e:
                raise AIError(f"OpenAI connection error: {e}") from e

        elapsed = int((time.monotonic() - t0) * 1000)
        data = resp.json()
        result = self._parse_openai_response(data, function_name)

        log_ai_response(
            function_name, model_label, elapsed,
            confidence=result.get("confidence"),
            finding_id=getattr(payload.get("finding"), "id", None),
        )
        result["_provider"] = "openai"
        result["_model"] = self.openai_model
        return result

    def _parse_openai_response(self, data: dict, function_name: str) -> dict:
        choices = data.get("choices", [])
        if not choices:
            raise AIError("Empty response from OpenAI")

        msg = choices[0].get("message", {})

        # Function call response
        tool_calls = msg.get("tool_calls", [])
        if tool_calls:
            args_str = tool_calls[0].get("function", {}).get("arguments", "{}")
            try:
                return json.loads(args_str)
            except json.JSONDecodeError as e:
                raise AIError(f"Invalid JSON in tool call arguments: {e}") from e

        # Plain content fallback (some models / providers)
        content = msg.get("content", "")
        return self._extract_json(content, function_name)

    # ─── Ollama ──────────────────────────────────────────────────────────────

    async def _ollama_call(self, function_name: str, payload: dict) -> dict:
        system_prompt = get_system_prompt(function_name)
        user_message = payload.get("prompt", "")

        body = {
            "model": self.ollama_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            "format": "json",
            "stream": False,
            "options": {"temperature": 0.1},
        }

        model_label = f"{self.ollama_model}@ollama"
        log_ai_request(function_name, model_label,
                       finding_id=getattr(payload.get("finding"), "id", None))
        t0 = time.monotonic()

        async with httpx.AsyncClient(timeout=self.timeout) as http:
            try:
                resp = await http.post(
                    f"{self.ollama_base_url}/api/chat",
                    json=body,
                )
                resp.raise_for_status()
            except httpx.ConnectError as e:
                raise AIError(
                    f"Cannot reach Ollama at {self.ollama_base_url}. "
                    "Is Ollama running? Run: ollama serve"
                ) from e
            except httpx.HTTPStatusError as e:
                raise AIError(f"Ollama API error {e.response.status_code}: {e.response.text[:200]}") from e

        elapsed = int((time.monotonic() - t0) * 1000)
        data = resp.json()
        content = data.get("message", {}).get("content", "")
        result = self._extract_json(content, function_name)

        log_ai_response(
            function_name, model_label, elapsed,
            confidence=result.get("confidence"),
            finding_id=getattr(payload.get("finding"), "id", None),
        )
        result["_provider"] = "ollama"
        result["_model"] = self.ollama_model
        return result

    # ─── Hybrid routing ──────────────────────────────────────────────────────

    async def _hybrid_call(self, function_name: str, payload: dict) -> dict:
        """Run both providers concurrently and merge results."""
        results = await asyncio.gather(
            self._ollama_call(function_name, payload),
            self._openai_call(function_name, payload),
            return_exceptions=True,
        )

        ollama_res, openai_res = results
        ollama_ok = isinstance(ollama_res, dict)
        openai_ok = isinstance(openai_res, dict)

        if openai_ok and ollama_ok:
            return self._merge_hybrid(ollama_res, openai_res, function_name)
        if openai_ok:
            openai_res["_hybrid_note"] = f"Ollama failed: {ollama_res}"
            return openai_res
        if ollama_ok:
            ollama_res["_hybrid_note"] = f"OpenAI failed: {openai_res}"
            return ollama_res
        raise AIError(f"Both providers failed. OpenAI: {openai_res}. Ollama: {ollama_res}")

    def _merge_hybrid(self, ollama: dict, openai: dict, function_name: str) -> dict:
        merged = dict(openai)  # Start with OpenAI as base

        if function_name == "analyze_finding":
            oa_conf = float(openai.get("confidence", 0.5))
            ol_conf = float(ollama.get("confidence", 0.5))
            # Weighted consensus
            consensus_conf = round(
                oa_conf * self._hybrid_weight + ol_conf * (1 - self._hybrid_weight), 3
            )
            merged["confidence"] = consensus_conf

            oa_ver = openai.get("verification", "")
            ol_ver = ollama.get("verification", "")
            if oa_ver != ol_ver:
                merged["_hybrid_disagreement"] = (
                    f"OpenAI: {oa_ver}, Ollama: {ol_ver} — deferring to OpenAI"
                )
            merged["_ollama_verification"] = ol_ver
            merged["_ollama_reasoning"] = ollama.get("reasoning", "")

        merged["_provider"] = "hybrid"
        merged["_openai_model"] = openai.get("_model", self.openai_model)
        merged["_ollama_model"] = ollama.get("_model", self.ollama_model)
        return merged

    # ─── JSON extraction ─────────────────────────────────────────────────────

    def _extract_json(self, text: str, function_name: str) -> dict:
        """Extract the first JSON object from a text response."""
        # Try direct parse
        text = text.strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Find JSON block
        import re
        m = re.search(r"\{[\s\S]+\}", text)
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                pass

        # Last resort: return a minimal valid fallback
        _log.warning("Could not parse JSON from AI response for %s", function_name)
        return {
            "error": "Could not parse structured response",
            "raw": text[:500],
            "confidence": 0.0,
            "verification": "possible",
            "reasoning": text[:200] if text else "No response from model",
            "risk_adjustment": "same",
        }

    # ─── Health check ────────────────────────────────────────────────────────

    async def health_check(self) -> dict[str, bool]:
        """Check which providers are reachable."""
        status: dict[str, bool] = {}

        if self.mode in ("openai", "hybrid"):
            try:
                async with httpx.AsyncClient(timeout=5) as http:
                    if self.openai_api_key:
                        r = await http.get(
                            f"{self.openai_base_url}/models",
                            headers={"Authorization": f"Bearer {self.openai_api_key}"},
                        )
                        status["openai"] = r.status_code == 200
                    else:
                        status["openai"] = False
            except Exception:
                status["openai"] = False

        if self.mode in ("ollama", "hybrid"):
            try:
                async with httpx.AsyncClient(timeout=3) as http:
                    r = await http.get(f"{self.ollama_base_url}/api/tags")
                    status["ollama"] = r.status_code == 200
            except Exception:
                status["ollama"] = False

        return status
