"""Runs CI/CD pipeline security tooling (poutine) against pipeline definitions
(Azure Pipelines, GitHub Actions, GitLab CI, etc.).

No LLM enrichment here, unlike sast/secrets/dependency: poutine's findings are
already explicit, rule-based hits (e.g. "unverified script execution") that don't
need narrative enrichment the way a bare CVE ID or a SAST snippet does.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from app.agents.base import BaseAgent
from app.core.security import redact_secrets
from app.observability.events import log_tool_execution, log_tool_execution_raw
from app.observability.metrics import record_tool_execution
from app.observability.tracing import repo_attrs, repo_identifier, tool_execution_span
from app.tools.poutine import PoutineAdapter
from app.tools.runner import run_all

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _now() -> datetime:
    return datetime.now(timezone.utc)


class CICDAgent(BaseAgent):
    name = "cicd"

    async def run(self, state: dict[str, Any]) -> dict[str, Any]:
        analysis_id = state.get("analysis_id", "unknown")
        target_path = state.get("local_repo_path")
        tools_config = state.get("tools_config", {})
        warnings = list(state.get("warnings", []))
        errors = list(state.get("errors", []))

        if not target_path:
            warnings.append("cicd: no local_repo_path in state, skipping tool execution")
            return {**state, "warnings": warnings}

        adapters = [PoutineAdapter()]

        try:
            tool_results = await run_all(adapters, target_path, tools_config)
        except Exception as exc:
            errors.append(f"cicd: tool execution failed unexpectedly: {exc}")
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
                warnings.append(f"cicd: tool '{result['tool_name']}' not installed/available")
            elif result.get("error"):
                warnings.append(f"cicd: tool '{result['tool_name']}' error: {result['error']}")

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

        findings.sort(key=lambda f: _SEVERITY_ORDER.get(f["severity"], 99))

        return {
            **state,
            "findings": [*state.get("findings", []), *findings],
            "tool_results": [*state.get("tool_results", []), *tool_result_dicts],
            "warnings": warnings,
            "errors": errors,
        }

    def _to_finding_dict(self, raw: dict[str, Any], tool_name: str) -> dict[str, Any]:
        code_snippet = raw.get("code_snippet")
        return {
            "id": str(uuid4()),
            "title": raw.get("title", f"{tool_name} finding"),
            "description": raw.get("description", ""),
            "severity": raw.get("severity", "medium"),
            "confidence": raw.get("confidence", "medium"),
            "category": raw.get("category", "cicd"),
            "cwe": raw.get("cwe"),
            "owasp": raw.get("owasp"),
            "file_path": raw.get("file_path"),
            "line_start": raw.get("line_start"),
            "line_end": raw.get("line_end"),
            "code_snippet": redact_secrets(code_snippet) if code_snippet else None,
            "evidence": [
                {
                    "description": f"Detected by {tool_name}",
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
