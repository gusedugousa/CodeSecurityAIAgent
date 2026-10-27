"""LangGraph state contract for the analysis graph, plus the initial-state factory."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, TypedDict

if TYPE_CHECKING:
    from app.core.config import Settings


class AnalysisState(TypedDict, total=False):
    analysis_id: str
    repo_url: str | None
    local_repo_path: str | None
    branch: str
    commit_sha: str | None
    local_path: str | None
    workspace_dir: str
    reports_dir: str
    analysis_profile: str
    model_profile: str
    enable_remediation: bool
    models_config: dict[str, Any]
    mock_mode: bool
    tools_config: dict[str, Any]
    repository_metadata: dict[str, Any] | None
    tool_results: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    remediation_suggestions: list[dict[str, Any]]
    report_artifacts: list[dict[str, Any]]
    errors: list[str]
    warnings: list[str]
    model_calls: list[dict[str, Any]]
    agent_results: list[dict[str, Any]]
    telemetry_context: dict[str, Any]
    severity_summary: dict[str, Any] | None
    executive_summary: str | None
    fatal_error: bool
    status: str
    current_node: str | None


def create_initial_state(analysis_id: str, request: dict[str, Any], settings: "Settings") -> AnalysisState:
    analysis_profile = request.get("analysis_profile", settings.default_analysis_profile)
    profile_config = settings.analysis_profiles.get(
        analysis_profile, settings.analysis_profiles.get(settings.default_analysis_profile, {})
    )
    enable_remediation = request.get(
        "enable_remediation", profile_config.get("enable_remediation", True)
    )

    return AnalysisState(
        analysis_id=analysis_id,
        repo_url=request.get("repo_url"),
        local_repo_path=None,
        branch=request.get("branch", "main"),
        commit_sha=request.get("commit_sha"),
        local_path=request.get("local_path"),
        workspace_dir=settings.workspace_dir,
        reports_dir=settings.reports_dir,
        analysis_profile=analysis_profile,
        model_profile=request.get("model_profile", "default"),
        enable_remediation=enable_remediation,
        models_config=settings.models,
        mock_mode=settings.models.get("mock_mode", True),
        tools_config=settings.tools,
        repository_metadata=None,
        tool_results=[],
        findings=[],
        remediation_suggestions=[],
        report_artifacts=[],
        errors=[],
        warnings=[],
        model_calls=[],
        agent_results=[],
        telemetry_context={},
        severity_summary=None,
        executive_summary=None,
        fatal_error=False,
        status="queued",
        current_node=None,
    )
