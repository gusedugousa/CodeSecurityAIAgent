"""SQLAlchemy 2.0 declarative ORM models plus converters to/from app.api.schemas Pydantic models.

JSON columns are used for nested/list fields (evidence, remediation) so the schema is
identical on SQLite and Postgres without dialect-specific types.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# All datetimes in this app are timezone-aware UTC (see app.core config/schemas); every
# datetime column must be declared timezone=True or Postgres rejects aware datetimes with
# "can't subtract offset-naive and offset-aware datetimes" (SQLite doesn't validate this).
_TZ_DATETIME = DateTime(timezone=True)

from app.api.schemas import (  # noqa: E402
    AnalysisJob,
    Evidence,
    Finding,
    RemediationSuggestion,
    ReportArtifact,
    SeveritySummary,
    ToolExecutionResult,
)


class Base(DeclarativeBase):
    pass


class AnalysisJobORM(Base):
    __tablename__ = "analysis_jobs"

    analysis_id: Mapped[str] = mapped_column(primary_key=True)
    repo_url: Mapped[str | None] = mapped_column(default=None)
    branch: Mapped[str] = mapped_column(default="main")
    commit_sha: Mapped[str | None] = mapped_column(default=None)
    local_path: Mapped[str | None] = mapped_column(default=None)
    analysis_profile: Mapped[str] = mapped_column(default="mvp-default")
    model_profile: Mapped[str] = mapped_column(default="default")
    enable_remediation: Mapped[bool] = mapped_column(default=True)
    status: Mapped[str] = mapped_column()
    current_node: Mapped[str | None] = mapped_column(default=None)
    progress_percent: Mapped[int | None] = mapped_column(default=None)
    error: Mapped[str | None] = mapped_column(default=None)
    created_at: Mapped[datetime] = mapped_column(_TZ_DATETIME)
    updated_at: Mapped[datetime] = mapped_column(_TZ_DATETIME)
    started_at: Mapped[datetime | None] = mapped_column(_TZ_DATETIME, default=None)
    completed_at: Mapped[datetime | None] = mapped_column(_TZ_DATETIME, default=None)


class FindingORM(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(primary_key=True)
    analysis_id: Mapped[str] = mapped_column(
        ForeignKey("analysis_jobs.analysis_id"), index=True
    )
    title: Mapped[str] = mapped_column()
    description: Mapped[str] = mapped_column()
    severity: Mapped[str] = mapped_column()
    confidence: Mapped[str] = mapped_column()
    category: Mapped[str] = mapped_column()
    cwe: Mapped[str | None] = mapped_column(default=None)
    owasp: Mapped[str | None] = mapped_column(default=None)
    file_path: Mapped[str | None] = mapped_column(default=None)
    line_start: Mapped[int | None] = mapped_column(default=None)
    line_end: Mapped[int | None] = mapped_column(default=None)
    code_snippet: Mapped[str | None] = mapped_column(default=None)
    evidence: Mapped[list[dict]] = mapped_column(JSON, default=list)
    attack_scenario: Mapped[str | None] = mapped_column(default=None)
    business_impact: Mapped[str | None] = mapped_column(default=None)
    recommendation: Mapped[str | None] = mapped_column(default=None)
    remediation: Mapped[dict | None] = mapped_column(JSON, default=None)
    source_tool: Mapped[str] = mapped_column()
    source_agent: Mapped[str] = mapped_column()
    validation_status: Mapped[str] = mapped_column(default="unvalidated")
    false_positive_reason: Mapped[str | None] = mapped_column(default=None)
    created_at: Mapped[datetime] = mapped_column(_TZ_DATETIME)


class ToolExecutionORM(Base):
    __tablename__ = "tool_executions"

    # stdout/stderr are intentionally dropped here: this table is a lean audit trail,
    # not a log store, and raw tool output can be arbitrarily large.
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(
        ForeignKey("analysis_jobs.analysis_id"), index=True
    )
    tool_name: Mapped[str] = mapped_column()
    category: Mapped[str] = mapped_column()
    available: Mapped[bool] = mapped_column()
    command: Mapped[str | None] = mapped_column(default=None)
    exit_code: Mapped[int | None] = mapped_column(default=None)
    duration_ms: Mapped[float] = mapped_column()
    started_at: Mapped[datetime] = mapped_column(_TZ_DATETIME)
    findings_count: Mapped[int] = mapped_column(default=0)
    error: Mapped[str | None] = mapped_column(default=None)
    raw_output_parsed: Mapped[bool] = mapped_column(default=False)


class ReportArtifactORM(Base):
    __tablename__ = "report_artifacts"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(
        ForeignKey("analysis_jobs.analysis_id"), index=True
    )
    report_type: Mapped[str] = mapped_column()
    path: Mapped[str] = mapped_column()
    generated_at: Mapped[datetime] = mapped_column(_TZ_DATETIME)
    size_bytes: Mapped[int | None] = mapped_column(default=None)


def analysis_job_orm_to_pydantic(orm: AnalysisJobORM) -> AnalysisJob:
    return AnalysisJob(
        analysis_id=orm.analysis_id,
        repo_url=orm.repo_url,
        branch=orm.branch,
        commit_sha=orm.commit_sha,
        local_path=orm.local_path,
        analysis_profile=orm.analysis_profile,
        model_profile=orm.model_profile,
        enable_remediation=orm.enable_remediation,
        status=orm.status,  # type: ignore[arg-type]
        created_at=orm.created_at,
        updated_at=orm.updated_at,
    )


def analysis_job_pydantic_to_orm(job: AnalysisJob) -> AnalysisJobORM:
    return AnalysisJobORM(
        analysis_id=job.analysis_id,
        repo_url=job.repo_url,
        branch=job.branch,
        commit_sha=job.commit_sha,
        local_path=job.local_path,
        analysis_profile=job.analysis_profile,
        model_profile=job.model_profile,
        enable_remediation=job.enable_remediation,
        status=job.status,
        created_at=job.created_at,
        updated_at=job.updated_at,
    )


def finding_orm_to_pydantic(orm: FindingORM) -> Finding:
    return Finding(
        id=orm.id,
        title=orm.title,
        description=orm.description,
        severity=orm.severity,  # type: ignore[arg-type]
        confidence=orm.confidence,  # type: ignore[arg-type]
        category=orm.category,
        cwe=orm.cwe,
        owasp=orm.owasp,
        file_path=orm.file_path,
        line_start=orm.line_start,
        line_end=orm.line_end,
        code_snippet=orm.code_snippet,
        evidence=[Evidence(**e) for e in (orm.evidence or [])],
        attack_scenario=orm.attack_scenario,
        business_impact=orm.business_impact,
        recommendation=orm.recommendation,
        remediation=(
            RemediationSuggestion(**orm.remediation) if orm.remediation is not None else None
        ),
        source_tool=orm.source_tool,
        source_agent=orm.source_agent,
        validation_status=orm.validation_status,  # type: ignore[arg-type]
        false_positive_reason=orm.false_positive_reason,
        created_at=orm.created_at,
    )


def finding_pydantic_to_orm(finding: Finding, analysis_id: str) -> FindingORM:
    return FindingORM(
        id=finding.id,
        analysis_id=analysis_id,
        title=finding.title,
        description=finding.description,
        severity=finding.severity,
        confidence=finding.confidence,
        category=finding.category,
        cwe=finding.cwe,
        owasp=finding.owasp,
        file_path=finding.file_path,
        line_start=finding.line_start,
        line_end=finding.line_end,
        code_snippet=finding.code_snippet,
        evidence=[e.model_dump(mode="json") for e in finding.evidence],
        attack_scenario=finding.attack_scenario,
        business_impact=finding.business_impact,
        recommendation=finding.recommendation,
        remediation=(
            finding.remediation.model_dump(mode="json") if finding.remediation is not None else None
        ),
        source_tool=finding.source_tool,
        source_agent=finding.source_agent,
        validation_status=finding.validation_status,
        false_positive_reason=finding.false_positive_reason,
        created_at=finding.created_at,
    )


def tool_execution_orm_to_pydantic(orm: ToolExecutionORM) -> ToolExecutionResult:
    return ToolExecutionResult(
        tool_name=orm.tool_name,
        category=orm.category,
        available=orm.available,
        command=orm.command,
        exit_code=orm.exit_code,
        stdout=None,
        stderr=None,
        duration_ms=orm.duration_ms,
        started_at=orm.started_at,
        findings_count=orm.findings_count,
        error=orm.error,
        raw_output_parsed=orm.raw_output_parsed,
    )


def tool_execution_pydantic_to_orm(result: ToolExecutionResult, analysis_id: str) -> ToolExecutionORM:
    return ToolExecutionORM(
        analysis_id=analysis_id,
        tool_name=result.tool_name,
        category=result.category,
        available=result.available,
        command=result.command,
        exit_code=result.exit_code,
        duration_ms=result.duration_ms,
        started_at=result.started_at,
        findings_count=result.findings_count,
        error=result.error,
        raw_output_parsed=result.raw_output_parsed,
    )


def report_artifact_orm_to_pydantic(orm: ReportArtifactORM) -> ReportArtifact:
    return ReportArtifact(
        analysis_id=orm.analysis_id,
        report_type=orm.report_type,  # type: ignore[arg-type]
        path=orm.path,
        generated_at=orm.generated_at,
        size_bytes=orm.size_bytes,
    )


def report_artifact_pydantic_to_orm(artifact: ReportArtifact) -> ReportArtifactORM:
    return ReportArtifactORM(
        analysis_id=artifact.analysis_id,
        report_type=artifact.report_type,
        path=artifact.path,
        generated_at=artifact.generated_at,
        size_bytes=artifact.size_bytes,
    )


def severity_summary_from_findings(findings: list[Finding]) -> SeveritySummary:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        counts[finding.severity] += 1
    return SeveritySummary(
        critical=counts["critical"],
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
        info=counts["info"],
        total=sum(counts.values()),
    )
