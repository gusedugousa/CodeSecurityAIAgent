"""Shared Pydantic v2 type contracts. No business logic lives here."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, model_validator


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AnalysisRequest(BaseModel):
    repo_url: str | None = None
    branch: str = "main"
    commit_sha: str | None = None
    local_path: str | None = None
    analysis_profile: str = "mvp-default"
    model_profile: str = "default"
    enable_remediation: bool = True

    @model_validator(mode="after")
    def _require_source(self) -> "AnalysisRequest":
        if not self.repo_url and not self.local_path:
            raise ValueError("at least one of repo_url or local_path must be provided")
        return self


class AnalysisStatus(BaseModel):
    analysis_id: str
    status: Literal["queued", "running", "completed", "failed", "partial"]
    current_node: str | None = None
    progress_percent: int | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None


class AnalysisJob(BaseModel):
    analysis_id: str
    repo_url: str | None = None
    branch: str = "main"
    commit_sha: str | None = None
    local_path: str | None = None
    analysis_profile: str = "mvp-default"
    model_profile: str = "default"
    enable_remediation: bool = True
    status: Literal["queued", "running", "completed", "failed", "partial"]
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class RepositoryMetadata(BaseModel):
    repo_url: str | None = None
    branch: str | None = None
    commit_sha: str | None = None
    local_path: str
    file_count: int
    total_size_bytes: int
    primary_languages: list[str] = Field(default_factory=list)
    cloned_at: datetime = Field(default_factory=_utcnow)


class SeveritySummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0


class Evidence(BaseModel):
    description: str
    snippet: str | None = None
    source: str | None = None


class RemediationSuggestion(BaseModel):
    finding_id: str
    summary: str
    patch_diff: str | None = None
    explanation: str
    generated_by_model: str | None = None


class Finding(BaseModel):
    id: str
    title: str
    description: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    confidence: Literal["high", "medium", "low"]
    category: str
    cwe: str | None = None
    owasp: str | None = None
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    code_snippet: str | None = None
    evidence: list[Evidence] = Field(default_factory=list)
    attack_scenario: str | None = None
    business_impact: str | None = None
    recommendation: str | None = None
    remediation: RemediationSuggestion | None = None
    source_tool: str
    source_agent: str
    validation_status: Literal["unvalidated", "confirmed", "false_positive"] = "unvalidated"
    false_positive_reason: str | None = None
    created_at: datetime = Field(default_factory=_utcnow)


class ToolExecutionResult(BaseModel):
    tool_name: str
    category: str
    available: bool
    command: str | None = None
    exit_code: int | None = None
    stdout: str | None = None
    stderr: str | None = None
    duration_ms: float
    started_at: datetime
    findings_count: int = 0
    error: str | None = None
    raw_output_parsed: bool = False


class AgentExecutionResult(BaseModel):
    agent_name: str
    status: Literal["success", "partial", "failed", "skipped"]
    started_at: datetime
    completed_at: datetime
    duration_ms: float
    findings_produced: int = 0
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class ModelCallMetadata(BaseModel):
    role: str = Field(description="e.g. 'analysis_model'")
    provider: str
    model_name: str
    token_count_input: int | None = None
    token_count_output: int | None = None
    cost_estimate: float | None = None
    duration_ms: float
    mock: bool = False
    timestamp: datetime = Field(default_factory=_utcnow)


class TelemetryContext(BaseModel):
    analysis_id: str
    repo_url: str | None = None
    branch: str | None = None
    commit_sha: str | None = None
    trace_id: str | None = None
    span_id: str | None = None


class ReportArtifact(BaseModel):
    analysis_id: str
    report_type: Literal["json", "markdown", "sarif", "csv", "csv_deduplicated"]
    path: str
    generated_at: datetime = Field(default_factory=_utcnow)
    size_bytes: int | None = None
