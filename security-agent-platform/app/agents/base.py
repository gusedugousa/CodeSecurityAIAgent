"""Abstract base class all subagents implement, plus the telemetry-wrapping entry point.

Future integration point: app.mcp.registry.get_mcp_registry() will let agents call out to
MCP-backed tools (GitHub, Jira, vulnerability DBs, etc.) once that layer is wired in.
"""

from __future__ import annotations

import time
import traceback
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from app.api.schemas import AgentExecutionResult
from app.observability.events import (
    log_agent_node_completed,
    log_agent_node_started,
    log_error,
)
from app.observability.metrics import record_agent_node_duration
from app.observability.tracing import agent_node_span, repo_attrs, repo_identifier


def _now() -> datetime:
    return datetime.now(timezone.utc)


class BaseAgent(ABC):
    name: str

    @abstractmethod
    async def run(self, state: dict[str, Any]) -> dict[str, Any]:
        """Execute this agent's work against the full LangGraph state.

        Must never raise for expected/non-fatal errors: catch exceptions internally
        and append to state["errors"] (analysis-degrading) or state["warnings"]
        (recoverable, e.g. a tool not installed). Always return a valid, updated
        state dict rather than mutating the input in place.
        """
        raise NotImplementedError

    async def execute_with_telemetry(self, state: dict[str, Any]) -> dict[str, Any]:
        analysis_id = state.get("analysis_id", "unknown")
        started_at = _now()
        repo = repo_identifier(**repo_attrs(state))
        log_agent_node_started(analysis_id, self.name, repo=repo)

        with agent_node_span(self.name, analysis_id, agent_name=self.name, **repo_attrs(state)):
            start_perf = time.perf_counter()
            try:
                new_state = await self.run(state)
            except Exception as exc:
                # A truly unexpected bug inside run() must never crash the whole graph -
                # convert it into a failed AgentExecutionResult and continue.
                duration_ms = (time.perf_counter() - start_perf) * 1000
                completed_at = _now()
                log_error(analysis_id, self.name, str(exc), exc=exc, repo=repo)
                log_agent_node_completed(analysis_id, self.name, "failed", duration_ms, repo=repo)
                record_agent_node_duration(self.name, duration_ms / 1000.0)

                result = AgentExecutionResult(
                    agent_name=self.name,
                    status="failed",
                    started_at=started_at,
                    completed_at=completed_at,
                    duration_ms=duration_ms,
                    findings_produced=0,
                    warnings=[],
                    errors=[f"{type(exc).__name__}: {exc}", traceback.format_exc(limit=5)],
                )
                agent_results = [*state.get("agent_results", []), result.model_dump(mode="json")]
                return {**state, "agent_results": agent_results}

            duration_ms = (time.perf_counter() - start_perf) * 1000
            completed_at = _now()

        prior_findings_count = len(state.get("findings", []))
        new_findings_count = len(new_state.get("findings", []))
        findings_produced = max(new_findings_count - prior_findings_count, 0)

        node_warnings = new_state.get("warnings", [])
        node_errors = new_state.get("errors", [])
        status: str
        if node_errors and node_errors != state.get("errors", []):
            status = "partial"
        else:
            status = "success"

        log_agent_node_completed(
            analysis_id, self.name, status, duration_ms, warnings=node_warnings, repo=repo
        )
        record_agent_node_duration(self.name, duration_ms / 1000.0)

        result = AgentExecutionResult(
            agent_name=self.name,
            status=status,
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=duration_ms,
            findings_produced=findings_produced,
            warnings=list(node_warnings),
            errors=[],
        )
        agent_results = [*new_state.get("agent_results", []), result.model_dump(mode="json")]
        return {**new_state, "agent_results": agent_results}
