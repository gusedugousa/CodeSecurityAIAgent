"""Builds and runs the linear LangGraph state machine: repo_ingestion -> sast -> secrets ->
dependency -> cicd -> remediation -> report, with a fatal-ingestion-error shortcut
straight to report.
"""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, START, StateGraph

from app.agents.cicd_agent import CICDAgent
from app.agents.dependency_agent import DependencyAgent
from app.agents.remediation_agent import RemediationAgent
from app.agents.repo_ingestion_agent import RepoIngestionAgent
from app.agents.report_agent import ReportAgent
from app.agents.sast_agent import SASTAgent
from app.agents.secrets_agent import SecretsAgent
from app.orchestration.state import AnalysisState

_compiled_graph: Any = None


async def _repo_ingestion_node(state: AnalysisState) -> dict[str, Any]:
    return await RepoIngestionAgent().execute_with_telemetry(state)


async def _sast_node(state: AnalysisState) -> dict[str, Any]:
    return await SASTAgent().execute_with_telemetry(state)


async def _secrets_node(state: AnalysisState) -> dict[str, Any]:
    return await SecretsAgent().execute_with_telemetry(state)


async def _dependency_node(state: AnalysisState) -> dict[str, Any]:
    return await DependencyAgent().execute_with_telemetry(state)


async def _cicd_node(state: AnalysisState) -> dict[str, Any]:
    return await CICDAgent().execute_with_telemetry(state)


async def _remediation_node(state: AnalysisState) -> dict[str, Any]:
    return await RemediationAgent().execute_with_telemetry(state)


async def _report_node(state: AnalysisState) -> dict[str, Any]:
    return await ReportAgent().execute_with_telemetry(state)


def _route_after_ingestion(state: AnalysisState) -> str:
    return "report" if state.get("fatal_error") else "sast"


def build_graph(checkpointer: Any | None = None) -> Any:
    graph = StateGraph(AnalysisState)

    graph.add_node("repo_ingestion", _repo_ingestion_node)
    graph.add_node("sast", _sast_node)
    graph.add_node("secrets", _secrets_node)
    graph.add_node("dependency", _dependency_node)
    graph.add_node("cicd", _cicd_node)
    graph.add_node("remediation", _remediation_node)
    graph.add_node("report", _report_node)

    graph.add_edge(START, "repo_ingestion")
    graph.add_conditional_edges(
        "repo_ingestion",
        _route_after_ingestion,
        {"report": "report", "sast": "sast"},
    )
    graph.add_edge("sast", "secrets")
    graph.add_edge("secrets", "dependency")
    graph.add_edge("dependency", "cicd")
    graph.add_edge("cicd", "remediation")
    graph.add_edge("remediation", "report")
    graph.add_edge("report", END)

    # MVP compiles without a real checkpointer (in-memory/default only); a durable
    # checkpointer from app/orchestration/checkpoints.py can be passed in later
    # without changing this function's shape.
    return graph.compile(checkpointer=checkpointer)


def _get_compiled_graph(checkpointer: Any | None = None) -> Any:
    global _compiled_graph
    if _compiled_graph is None or checkpointer is not None:
        _compiled_graph = build_graph(checkpointer=checkpointer)
    return _compiled_graph


async def run_analysis_graph(
    initial_state: AnalysisState, checkpointer: Any | None = None
) -> AnalysisState:
    graph = _get_compiled_graph(checkpointer)
    final_state = await graph.ainvoke(initial_state)
    return final_state
