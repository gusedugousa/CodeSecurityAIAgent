"""Runs secret-scanning tool adapters (Gitleaks, TruffleHog) and flags likely placeholders."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.agents.base import BaseAgent
from app.core.security import redact_secrets
from app.langchain_utils.parsers import parse_json_response
from app.langchain_utils.prompts import build_secrets_triage_prompt
from app.models.litellm_client import LiteLLMModelClient
from app.models.routing import ModelRouter
from app.models.schemas import ModelRequest
from app.observability.events import (
    log_model_call,
    log_model_call_raw,
    log_tool_execution,
    log_tool_execution_raw,
)
from app.observability.metrics import record_llm_call, record_tool_execution
from app.observability.tracing import (
    model_call_span,
    repo_attrs,
    repo_identifier,
    tool_execution_span,
)
from app.tools.gitleaks import GitleaksAdapter
from app.tools.runner import run_all
from app.tools.trufflehog import TrufflehogAdapter

_PLACEHOLDER_HINTS = ("example", "test", "dummy", "xxx", "placeholder", "fake", "sample")


def _now() -> datetime:
    return datetime.now(UTC)


def _looks_like_placeholder(finding: dict[str, Any]) -> bool:
    haystack = " ".join(
        str(finding.get(field) or "")
        for field in ("title", "description", "file_path", "code_snippet")
    ).lower()
    return any(hint in haystack for hint in _PLACEHOLDER_HINTS)


class SecretsAgent(BaseAgent):
    name = "secrets"

    async def run(self, state: dict[str, Any]) -> dict[str, Any]:
        analysis_id = state.get("analysis_id", "unknown")
        target_path = state.get("local_repo_path")
        tools_config = state.get("tools_config", {})
        warnings = list(state.get("warnings", []))
        errors = list(state.get("errors", []))

        if not target_path:
            warnings.append("secrets: no local_repo_path in state, skipping tool execution")
            return {**state, "warnings": warnings}

        adapters = [GitleaksAdapter(), TrufflehogAdapter()]

        try:
            tool_results = await run_all(adapters, target_path, tools_config)
        except Exception as exc:
            errors.append(f"secrets: tool execution failed unexpectedly: {exc}")
            return {**state, "errors": errors}

        findings: list[dict[str, Any]] = []
        tool_result_dicts: list[dict[str, Any]] = []

        repo = repo_identifier(**repo_attrs(state))
        for result in tool_results:
            with tool_execution_span(
                result["tool_name"], analysis_id, category=result["category"], **repo_attrs(state)
            ):
                log_tool_execution(
                    analysis_id,
                    result["tool_name"],
                    result["available"],
                    result.get("exit_code"),
                    result["duration_ms"],
                    result["findings_count"],
                    repo=repo,
                )
                record_tool_execution(result["tool_name"], result["duration_ms"] / 1000.0)
                log_tool_execution_raw(
                    analysis_id,
                    result["tool_name"],
                    result.get("command"),
                    result.get("stdout"),
                    result.get("stderr"),
                    repo=repo,
                )

            if not result["available"]:
                warnings.append(f"secrets: tool '{result['tool_name']}' not installed/available")
            elif result.get("error"):
                warnings.append(f"secrets: tool '{result['tool_name']}' error: {result['error']}")

            tool_result_dicts.append(
                {
                    "tool_name": result["tool_name"],
                    "category": result["category"],
                    "available": result["available"],
                    "command": result.get("command"),
                    "exit_code": result.get("exit_code"),
                    "stdout": result.get("stdout"),
                    "stderr": result.get("stderr"),
                    "duration_ms": result["duration_ms"],
                    "started_at": result["started_at"],
                    "findings_count": result["findings_count"],
                    "error": result.get("error"),
                    "raw_output_parsed": result["raw_output_parsed"],
                }
            )

            for raw_finding in result.get("findings", []):
                findings.append(self._to_finding_dict(raw_finding, result["tool_name"]))

        model_calls = list(state.get("model_calls", []))
        try:
            await self._triage_findings(state, findings, model_calls, analysis_id)
        except Exception as exc:
            warnings.append(f"secrets: LLM triage failed, falling back to heuristics only: {exc}")

        return {
            **state,
            "findings": [*state.get("findings", []), *findings],
            "tool_results": [*state.get("tool_results", []), *tool_result_dicts],
            "model_calls": model_calls,
            "warnings": warnings,
            "errors": errors,
        }

    def _to_finding_dict(self, raw: dict[str, Any], tool_name: str) -> dict[str, Any]:
        # Defense in depth: adapters already redact secret material, but we redact again
        # here so a future adapter change can never leak a raw secret through this agent.
        code_snippet = raw.get("code_snippet")
        redacted_snippet = redact_secrets(code_snippet) if code_snippet else None
        return {
            "id": str(uuid4()),
            "title": raw.get("title", f"{tool_name} finding"),
            "description": redact_secrets(raw.get("description", "")),
            "severity": raw.get("severity", "critical"),
            "confidence": raw.get("confidence", "high"),
            "category": raw.get("category", "secrets"),
            "cwe": raw.get("cwe", "CWE-798"),
            "owasp": raw.get("owasp"),
            "file_path": raw.get("file_path"),
            "line_start": raw.get("line_start"),
            "line_end": raw.get("line_end"),
            "code_snippet": redacted_snippet,
            "evidence": [
                {
                    "description": f"Detected by {tool_name} secret scanning",
                    "snippet": redacted_snippet,
                    "source": tool_name,
                }
            ],
            "attack_scenario": None,
            "business_impact": None,
            "recommendation": "Rotate this credential immediately and remove it from source control history.",
            "remediation": None,
            "source_tool": raw.get("source_tool", tool_name),
            "source_agent": self.name,
            "validation_status": "unvalidated",
            "false_positive_reason": None,
            "created_at": _now(),
        }

    async def _triage_findings(
        self,
        state: dict[str, Any],
        findings: list[dict[str, Any]],
        model_calls: list[dict[str, Any]],
        analysis_id: str,
    ) -> None:
        if not findings:
            return

        client = LiteLLMModelClient(state.get("models_config", {}), state.get("mock_mode", True))
        router = ModelRouter(state.get("models_config", {}))
        model_name = router.resolve("cheap_classifier_model", state.get("model_profile", "default"))

        for finding in findings:
            heuristic_placeholder = _looks_like_placeholder(finding)

            finding_summary = (
                f"title={finding['title']} file={finding.get('file_path')} "
                f"rule/detector context suggests placeholder={heuristic_placeholder}"
            )
            prompt = build_secrets_triage_prompt(finding_summary)
            request = ModelRequest(
                messages=[{"role": "user", "content": prompt}],
                role="cheap_classifier_model",
                analysis_id=analysis_id,
            )

            try:
                with model_call_span(
                    "cheap_classifier_model", model_name, analysis_id, **repo_attrs(state)
                ):
                    response = await client.call(request, model_name=model_name)
            except Exception:
                # Fall back to the heuristic alone if the model call itself fails.
                if heuristic_placeholder:
                    finding["validation_status"] = "false_positive"
                    finding["false_positive_reason"] = "Heuristic match on placeholder/test keywords."
                continue

            repo = repo_identifier(**repo_attrs(state))
            log_model_call(
                analysis_id,
                response.metadata.role,
                response.metadata.provider,
                response.metadata.model_name,
                response.metadata.token_count_input,
                response.metadata.token_count_output,
                response.metadata.cost_estimate,
                response.metadata.duration_ms,
                response.metadata.mock,
                repo=repo,
            )
            record_llm_call(
                response.metadata.role,
                response.metadata.model_name,
                response.metadata.token_count_input,
                response.metadata.token_count_output,
                response.metadata.cost_estimate,
            )
            log_model_call_raw(
                analysis_id,
                "cheap_classifier_model",
                model_name,
                prompt,
                response.content,
                repo=repo,
            )
            model_calls.append(response.metadata.model_dump(mode="json"))

            parsed = parse_json_response(response.content, fallback={})
            looks_placeholder = bool(parsed.get("is_placeholder")) or heuristic_placeholder
            if looks_placeholder:
                finding["validation_status"] = "false_positive"
                finding["false_positive_reason"] = (
                    parsed.get("rationale") or "Looks like a placeholder/test/example credential."
                )
