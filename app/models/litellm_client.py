"""LiteLLM-backed model client with a deterministic mock mode for zero-API-key operation."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

import litellm
from tenacity import AsyncRetrying, retry_if_exception_type, stop_after_attempt, wait_fixed

from app.api.schemas import ModelCallMetadata
from app.core.errors import ModelCallError
from app.core.security import redact_secrets
from app.models.schemas import ModelRequest, ModelResponse

_MOCK_CONTENT_BY_ROLE: dict[str, str] = {
    "coordinator_model": '{"summary": "mock coordination plan", "next_nodes": []}',
    "analysis_model": '{"summary": "mock analysis", "findings_reviewed": 0}',
    "remediation_model": (
        '{"summary": "mock remediation", "patch_diff": "", '
        '"explanation": "mock remediation suggestion, no real model called"}'
    ),
    "reporting_model": '{"summary": "mock report", "sections": []}',
    "cheap_classifier_model": '{"label": "mock", "confidence": 0.0}',
}

_DEFAULT_MOCK_CONTENT = '{"summary": "mock response", "mock": true}'


def _estimate_tokens(text: str) -> int:
    return max(len(text) // 4, 0)


def _provider_from_model_name(model_name: str) -> str:
    return model_name.split("/", 1)[0] if "/" in model_name else "unknown"


def _cost_estimate(
    model_name: str,
    tokens_in: int,
    tokens_out: int,
    cost_table: dict[str, Any],
) -> float:
    rates = cost_table.get(model_name)
    if not rates:
        return 0.0
    input_rate = rates.get("input", 0.0)
    output_rate = rates.get("output", 0.0)
    return round((tokens_in / 1000.0) * input_rate + (tokens_out / 1000.0) * output_rate, 6)


class LiteLLMModelClient:
    def __init__(self, models_config: dict[str, Any], mock_mode: bool) -> None:
        self._config = models_config
        self._mock_mode = mock_mode
        self._cost_table: dict[str, Any] = models_config.get("cost_table_per_1k_tokens", {})
        request_defaults = models_config.get("request_defaults", {})
        self._timeout_seconds: float = request_defaults.get("timeout_seconds", 60)
        self._retry_count: int = request_defaults.get("retry_count", 2)
        self._retry_backoff_seconds: float = request_defaults.get("retry_backoff_seconds", 2)

    async def call(self, request: ModelRequest, model_name: str | None = None) -> ModelResponse:
        resolved_model = model_name or self._role_fallback_model(request.role)

        if self._mock_mode or resolved_model.startswith("mock/"):
            return self._mock_call(request, resolved_model)

        return await self._real_call(request, resolved_model)

    def _role_fallback_model(self, role: str) -> str:
        return f"mock/{role}"

    def _mock_call(self, request: ModelRequest, model_name: str) -> ModelResponse:
        start = time.perf_counter()
        content = _MOCK_CONTENT_BY_ROLE.get(request.role, _DEFAULT_MOCK_CONTENT)
        duration_ms = (time.perf_counter() - start) * 1000

        input_text = "".join(m.get("content", "") for m in request.messages)
        metadata = ModelCallMetadata(
            role=request.role,
            provider=_provider_from_model_name(model_name),
            model_name=model_name,
            token_count_input=_estimate_tokens(input_text),
            token_count_output=_estimate_tokens(content),
            cost_estimate=0.0,
            duration_ms=duration_ms,
            mock=True,
            timestamp=datetime.now(UTC),
        )
        return ModelResponse(content=content, metadata=metadata)

    async def _real_call(self, request: ModelRequest, model_name: str) -> ModelResponse:
        # Redact before the request leaves the process: prompts may embed raw code snippets
        # that contain credentials pulled from the target repository.
        safe_messages = [
            {**m, "content": redact_secrets(m.get("content", ""))} for m in request.messages
        ]

        start = time.perf_counter()
        try:
            async for attempt in AsyncRetrying(
                stop=stop_after_attempt(self._retry_count + 1),
                wait=wait_fixed(self._retry_backoff_seconds),
                retry=retry_if_exception_type(Exception),
                reraise=True,
            ):
                with attempt:
                    response = await litellm.acompletion(
                        model=model_name,
                        messages=safe_messages,
                        timeout=self._timeout_seconds,
                        max_tokens=request.max_tokens,
                        temperature=request.temperature,
                    )
        except Exception as exc:
            raise ModelCallError(
                f"model call failed for role '{request.role}': {exc}",
                role=request.role,
                model_name=model_name,
            ) from exc

        duration_ms = (time.perf_counter() - start) * 1000

        content = response.choices[0].message.content or ""
        usage = getattr(response, "usage", None)
        tokens_in = getattr(usage, "prompt_tokens", None) if usage else None
        tokens_out = getattr(usage, "completion_tokens", None) if usage else None

        cost = _cost_estimate(model_name, tokens_in or 0, tokens_out or 0, self._cost_table)

        metadata = ModelCallMetadata(
            role=request.role,
            provider=_provider_from_model_name(model_name),
            model_name=model_name,
            token_count_input=tokens_in,
            token_count_output=tokens_out,
            cost_estimate=cost,
            duration_ms=duration_ms,
            mock=False,
            timestamp=datetime.now(UTC),
        )
        return ModelResponse(content=content, metadata=metadata)
