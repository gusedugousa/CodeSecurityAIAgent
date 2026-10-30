"""Runs SAST tool adapters (Semgrep, Bandit) and enriches top findings with an LLM triage pass."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.agents.base import BaseAgent
from app.core.security import redact_secrets
from app.langchain_utils.prompts import build_sast_analysis_prompt
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
from app.tools.bandit import BanditAdapter
from app.tools.meziantou import MeziantouAnalyzerAdapter
from app.tools.runner import run_all
from app.tools.semgrep import SemgrepAdapter

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_TOP_N_FOR_LLM_TRIAGE = 5  # cap LLM calls to control cost - batch top findings, not one call per finding


def _now() -> datetime:
    return datetime.now(UTC)


class SASTAgent(BaseAgent):
    name = "sast"

    async def run(self, state: dict[str, Any]) -> dict[str, Any]:
        analysis_id = state.get("analysis_id", "unknown")
        target_path = state.get("local_repo_path")
        tools_config = state.get("tools_config", {})
        warnings = list(state.get("warnings", []))
        errors = list(state.get("errors", []))

        if not target_path:
            warnings.append("sast: no local_repo_path in state, skipping tool execution")
            return {**state, "warnings": warnings}

        adapters = [SemgrepAdapter(), BanditAdapter(), MeziantouAnalyzerAdapter()]

        try:
            tool_results = await run_all(adapters, target_path, tools_config)
        except Exception as exc:
            errors.append(f"sast: tool execution failed unexpectedly: {exc}")
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
                warnings.append(f"sast: tool '{result['tool_name']}' not installed/available")
            elif result.get("error"):
                warnings.append(f"sast: tool '{result['tool_name']}' error: {result['error']}")

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
                finding = self._to_finding_dict(raw_finding, result["tool_name"])
                findings.append(finding)

        findings.sort(key=lambda f: _SEVERITY_ORDER.get(f["severity"], 99))
        model_calls = list(state.get("model_calls", []))

        try:
            await self._enrich_top_findings(state, findings, model_calls, analysis_id)
        except Exception as exc:
            warnings.append(f"sast: LLM enrichment failed, continuing without AI summaries: {exc}")

        return {
            **state,
            "findings": [*state.get("findings", []), *findings],
            "tool_results": [*state.get("tool_results", []), *tool_result_dicts],
            "model_calls": model_calls,
            "warnings": warnings,
            "errors": errors,
        }

    def _to_finding_dict(self, raw: dict[str, Any], tool_name: str) -> dict[str, Any]:
        code_snippet = raw.get("code_snippet")
        return {
            "id": str(uuid4()),
            "title": raw.get("title", f"{tool_name} finding"),
            "description": raw.get("description", ""),
            "severity": raw.get("severity", "info"),
            "confidence": raw.get("confidence", "medium"),
            "category": raw.get("category", "sast"),
            "cwe": raw.get("cwe"),
            "owasp": raw.get("owasp"),
            "file_path": raw.get("file_path"),
            "line_start": raw.get("line_start"),
            "line_end": raw.get("line_end"),
            "code_snippet": redact_secrets(code_snippet) if code_snippet else None,
            "evidence": [
                {
                    "description": f"Detected by {tool_name} static analysis",
                    "snippet": redact_secrets(code_snippet) if code_snippet else None,
                    "source": tool_name,
                }
            ],
            "attack_scenario": None,
            "business_impact": None,
            "recommendation": raw.get("recommendation"),
            "remediation": None,
            "source_tool": raw.get("source_tool", tool_name),
            "source_agent": self.name,
            "validation_status": "unvalidated",
            "false_positive_reason": None,
            "created_at": _now(),
        }

    async def _enrich_top_findings(
        self,
        state: dict[str, Any],
        findings: list[dict[str, Any]],
        model_calls: list[dict[str, Any]],
        analysis_id: str,
    ) -> None:
        top_findings = findings[:_TOP_N_FOR_LLM_TRIAGE]
        if not top_findings:
            return

        client = LiteLLMModelClient(state.get("models_config", {}), state.get("mock_mode", True))
        router = ModelRouter(state.get("models_config", {}))
        model_name = router.resolve("analysis_model", state.get("model_profile", "default"))

        tool_findings_summary = "\n".join(
            f"- [{f['severity']}] {f['title']}: {f['description']}" for f in top_findings
        )
        code_snippet = "\n---\n".join(f.get("code_snippet") or "" for f in top_findings)
        prompt = build_sast_analysis_prompt(code_snippet, tool_findings_summary)

        request = ModelRequest(
            messages=[{"role": "user", "content": prompt}],
            role="analysis_model",
            analysis_id=analysis_id,
        )

        with model_call_span("analysis_model", model_name, analysis_id, **repo_attrs(state)):
            response = await client.call(request, model_name=model_name)

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
            analysis_id, "analysis_model", model_name, prompt, response.content, repo=repo
        )
        model_calls.append(response.metadata.model_dump(mode="json"))

        summary_text = response.content
        for finding in top_findings:
            finding["attack_scenario"] = summary_text
            finding["business_impact"] = summary_text
