"""Computes severity_summary + executive_summary in state.

Does NOT write files: actual JSON/Markdown/SARIF generation lives in app/reports/*.py
(built in parallel) and is invoked from the API/orchestration layer after the graph
completes, consuming state["severity_summary"]/state["executive_summary"]/state["findings"].
report_artifacts is left as an empty placeholder list for the API layer to populate with
ReportArtifact dicts once files are actually written to disk.
"""

from __future__ import annotations

import json
from typing import Any

from app.agents.base import BaseAgent
from app.langchain_utils.prompts import build_report_summary_prompt
from app.models.litellm_client import LiteLLMModelClient
from app.models.routing import ModelRouter
from app.models.schemas import ModelRequest
from app.observability.events import log_model_call, log_model_call_raw
from app.observability.metrics import record_findings, record_llm_call
from app.observability.tracing import model_call_span, repo_attrs, repo_identifier

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_TOP_N_FOR_SUMMARY = 10


class ReportAgent(BaseAgent):
    name = "report"

    async def run(self, state: dict[str, Any]) -> dict[str, Any]:
        analysis_id = state.get("analysis_id", "unknown")
        findings = state.get("findings", [])
        warnings = list(state.get("warnings", []))
        model_calls = list(state.get("model_calls", []))

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            severity = finding.get("severity", "info")
            if severity in severity_counts:
                severity_counts[severity] += 1
        severity_summary = {**severity_counts, "total": len(findings)}
        record_findings(len(findings), severity_counts)

        executive_summary: str | None = None
        try:
            executive_summary = await self._build_executive_summary(
                state, findings, severity_summary, model_calls, analysis_id
            )
        except Exception as exc:
            warnings.append(f"report: executive summary generation failed: {exc}")

        return {
            **state,
            "severity_summary": severity_summary,
            "executive_summary": executive_summary,
            "report_artifacts": state.get("report_artifacts", []),
            "model_calls": model_calls,
            "warnings": warnings,
        }

    async def _build_executive_summary(
        self,
        state: dict[str, Any],
        findings: list[dict[str, Any]],
        severity_summary: dict[str, int],
        model_calls: list[dict[str, Any]],
        analysis_id: str,
    ) -> str:
        client = LiteLLMModelClient(state.get("models_config", {}), state.get("mock_mode", True))
        router = ModelRouter(state.get("models_config", {}))
        model_name = router.resolve("reporting_model", state.get("model_profile", "default"))

        top_findings = sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.get("severity"), 99))[
            :_TOP_N_FOR_SUMMARY
        ]
        top_findings_summary = "\n".join(
            f"- [{f.get('severity')}] {f.get('title')}" for f in top_findings
        )

        prompt = build_report_summary_prompt(json.dumps(severity_summary), top_findings_summary)
        request = ModelRequest(
            messages=[{"role": "user", "content": prompt}],
            role="reporting_model",
            analysis_id=analysis_id,
        )

        with model_call_span("reporting_model", model_name, analysis_id, **repo_attrs(state)):
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
            analysis_id, "reporting_model", model_name, prompt, response.content, repo=repo
        )
        model_calls.append(response.metadata.model_dump(mode="json"))

        return response.content
