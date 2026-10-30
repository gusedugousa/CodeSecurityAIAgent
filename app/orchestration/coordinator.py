"""Top-level orchestration entry point invoked by the API layer's background task."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from app.orchestration.graph import run_analysis_graph
from app.orchestration.state import AnalysisState, create_initial_state

if TYPE_CHECKING:
    from app.core.config import Settings


class CoordinatorAgent:
    async def run(self, analysis_id: str, request: dict[str, Any], settings: Settings) -> dict[str, Any]:
        state = create_initial_state(analysis_id, request, settings)
        state["status"] = "running"
        state["telemetry_context"] = {
            "analysis_id": analysis_id,
            "repo_url": state.get("repo_url"),
            "branch": state.get("branch"),
            "commit_sha": state.get("commit_sha"),
        }

        final_state: AnalysisState = await run_analysis_graph(state)

        final_state["status"] = self._resolve_status(final_state)
        return final_state

    def _resolve_status(self, state: dict[str, Any]) -> str:
        if state.get("fatal_error"):
            return "failed"
        if state.get("errors"):
            return "partial" if state.get("findings") else "failed"
        return "completed"


async def coordinate_analysis(analysis_id: str, request: dict[str, Any], settings: Settings) -> dict[str, Any]:
    return await CoordinatorAgent().run(analysis_id, request, settings)
