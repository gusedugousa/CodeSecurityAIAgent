"""Generates remediation suggestions for high-severity findings via remediation_model."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.agents.base import BaseAgent
from app.api.schemas import AgentExecutionResult
from app.langchain_utils.parsers import parse_remediation_response
from app.langchain_utils.prompts import build_remediation_prompt
from app.models.litellm_client import LiteLLMModelClient
from app.models.routing import ModelRouter
from app.models.schemas import ModelRequest
from app.observability.events import log_model_call, log_model_call_raw
from app.observability.metrics import record_llm_call
from app.observability.tracing import model_call_span, repo_attrs, repo_identifier

_REMEDIATION_SEVERITIES = {"critical", "high"}
_MAX_REMEDIATION_CALLS = 10  # cap total LLM calls per run to control cost


def _now() -> datetime:
    return datetime.now(timezone.utc)


class RemediationAgent(BaseAgent):
    name = "remediation"

    async def run(self, state: dict[str, Any]) -> dict[str, Any]:
        if not state.get("enable_remediation", True):
            started_at = _now()
            result = AgentExecutionResult(
                agent_name=self.name,
                status="skipped",
                started_at=started_at,
                completed_at=_now(),
                duration_ms=0.0,
                findings_produced=0,
                warnings=[],
                errors=[],
            )
            agent_results = [*state.get("agent_results", []), result.model_dump(mode="json")]
            return {**state, "agent_results": agent_results}

        analysis_id = state.get("analysis_id", "unknown")
        findings = list(state.get("findings", []))
        warnings = list(state.get("warnings", []))
        model_calls = list(state.get("model_calls", []))
        remediation_suggestions = list(state.get("remediation_suggestions", []))

        candidates = [f for f in findings if f.get("severity") in _REMEDIATION_SEVERITIES]
        candidates = candidates[:_MAX_REMEDIATION_CALLS]

        if not candidates:
            return {**state, "warnings": warnings}

        try:
            client = LiteLLMModelClient(state.get("models_config", {}), state.get("mock_mode", True))
            router = ModelRouter(state.get("models_config", {}))
            model_name = router.resolve("remediation_model", state.get("model_profile", "default"))
        except Exception as exc:
            warnings.append(f"remediation: failed to initialize model client: {exc}")
            return {**state, "warnings": warnings}

        findings_by_id = {f["id"]: f for f in findings}

        for finding in candidates:
            try:
                prompt = build_remediation_prompt(
                    finding_title=finding["title"],
                    finding_description=finding["description"],
                    code_snippet=finding.get("code_snippet") or "",
                    cwe=finding.get("cwe"),
                )
                request = ModelRequest(
                    messages=[{"role": "user", "content": prompt}],
                    role="remediation_model",
                    analysis_id=analysis_id,
                )

                with model_call_span(
                    "remediation_model", model_name, analysis_id, **repo_attrs(state)
                ):
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
                    analysis_id,
                    "remediation_model",
                    model_name,
                    prompt,
                    response.content,
                    repo=repo,
                )
                model_calls.append(response.metadata.model_dump(mode="json"))

                parsed = parse_remediation_response(response.content, finding["id"])
                parsed["generated_by_model"] = response.metadata.model_name

                remediation_suggestions.append(parsed)
                findings_by_id[finding["id"]]["remediation"] = parsed
            except Exception as exc:
                warnings.append(
                    f"remediation: failed to generate suggestion for finding {finding.get('id')}: {exc}"
                )

        updated_findings = [findings_by_id.get(f["id"], f) for f in findings]

        return {
            **state,
            "findings": updated_findings,
            "remediation_suggestions": remediation_suggestions,
            "model_calls": model_calls,
            "warnings": warnings,
        }
