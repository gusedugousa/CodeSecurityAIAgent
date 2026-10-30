"""Analysis job creation and status endpoints."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, BackgroundTasks

from app.api.schemas import AnalysisJob, AnalysisRequest, AnalysisStatus
from app.core.config import get_settings
from app.core.errors import AnalysisNotFoundError
from app.core.logging import get_logger
from app.observability.events import log_analysis_completed, log_analysis_started
from app.observability.metrics import record_analysis_completed, record_analysis_started
from app.observability.tracing import repo_attrs, repo_identifier
from app.orchestration.coordinator import coordinate_analysis
from app.persistence.db import session_scope
from app.persistence.repositories import (
    AnalysisJobRepository,
    FindingRepository,
    ReportArtifactRepository,
    ToolExecutionRepository,
)
from app.reports.csv_report import generate_csv_report, write_csv_report
from app.reports.dedup_csv_report import generate_dedup_csv_report, write_dedup_csv_report
from app.reports.json_report import generate_json_report, write_json_report
from app.reports.markdown_report import generate_markdown_report, write_markdown_report
from app.reports.sarif_report import generate_sarif_report, write_sarif_report

router = APIRouter(tags=["analysis"])
logger = get_logger(__name__)


async def _run_analysis_job(analysis_id: str, request_dict: dict) -> None:
    import time

    settings = get_settings()
    started_repo = repo_identifier(**repo_attrs(request_dict))
    log_analysis_started(
        analysis_id,
        request_dict.get("repo_url"),
        request_dict.get("branch", "main"),
        repo=started_repo,
    )
    record_analysis_started()

    async with session_scope() as session:
        await AnalysisJobRepository(session).mark_started(analysis_id)

    start = time.perf_counter()
    final_state = await coordinate_analysis(analysis_id, request_dict, settings)
    duration_seconds = time.perf_counter() - start

    findings = final_state.get("findings", [])
    tool_results = final_state.get("tool_results", [])
    status = final_state.get("status", "completed")

    async with session_scope() as session:
        job_repo = AnalysisJobRepository(session)
        await job_repo.update_status(
            analysis_id,
            status=status,
            current_node="report",
            error="; ".join(final_state.get("errors", [])) or None,
        )
        await job_repo.mark_completed(analysis_id, status)

        if findings:
            from app.api.schemas import Finding

            await FindingRepository(session).bulk_create(
                [Finding(**f) for f in findings], analysis_id
            )
        if tool_results:
            from app.api.schemas import ToolExecutionResult

            await ToolExecutionRepository(session).bulk_create(
                [ToolExecutionResult(**t) for t in tool_results], analysis_id
            )

    reports_dir = f"{settings.reports_dir}/{analysis_id}"
    warnings = final_state.get("warnings", [])
    repository_metadata = final_state.get("repository_metadata")
    severity_summary = final_state.get("severity_summary")
    executive_summary = final_state.get("executive_summary")

    json_report = generate_json_report(
        analysis_id, findings, repository_metadata, severity_summary, tool_results, warnings
    )
    md_report = generate_markdown_report(
        analysis_id,
        findings,
        repository_metadata,
        severity_summary,
        tool_results,
        executive_summary,
        warnings,
    )
    sarif_report = generate_sarif_report(analysis_id, findings, repository_metadata, tool_results)
    csv_report = generate_csv_report(analysis_id, findings, repository_metadata)
    dedup_csv_report = generate_dedup_csv_report(analysis_id, findings, repository_metadata)

    json_size = write_json_report(json_report, f"{reports_dir}/report.json")
    md_size = write_markdown_report(md_report, f"{reports_dir}/report.md")
    sarif_size = write_sarif_report(sarif_report, f"{reports_dir}/report.sarif.json")
    csv_size = write_csv_report(csv_report, f"{reports_dir}/report.csv")
    dedup_csv_size = write_dedup_csv_report(
        dedup_csv_report, f"{reports_dir}/report.deduplicated.csv"
    )

    async with session_scope() as session:
        from app.api.schemas import ReportArtifact

        artifact_repo = ReportArtifactRepository(session)
        now = datetime.now(UTC)
        for report_type, path, size in (
            ("json", f"{reports_dir}/report.json", json_size),
            ("markdown", f"{reports_dir}/report.md", md_size),
            ("sarif", f"{reports_dir}/report.sarif.json", sarif_size),
            ("csv", f"{reports_dir}/report.csv", csv_size),
            ("csv_deduplicated", f"{reports_dir}/report.deduplicated.csv", dedup_csv_size),
        ):
            await artifact_repo.create(
                ReportArtifact(
                    analysis_id=analysis_id,
                    report_type=report_type,
                    path=path,
                    generated_at=now,
                    size_bytes=size,
                )
            )

    record_analysis_completed(duration_seconds, status)
    log_analysis_completed(
        analysis_id,
        status,
        duration_seconds * 1000,
        len(findings),
        repo=repo_identifier(**repo_attrs(final_state)),
    )


@router.post("/analysis", status_code=202)
async def create_analysis(request: AnalysisRequest, background_tasks: BackgroundTasks) -> dict:
    analysis_id = str(uuid.uuid4())

    job = AnalysisJob(
        analysis_id=analysis_id,
        repo_url=request.repo_url,
        branch=request.branch,
        commit_sha=request.commit_sha,
        local_path=request.local_path,
        analysis_profile=request.analysis_profile,
        model_profile=request.model_profile,
        enable_remediation=request.enable_remediation,
        status="queued",
    )

    async with session_scope() as session:
        await AnalysisJobRepository(session).create(job)

    background_tasks.add_task(_run_analysis_job, analysis_id, request.model_dump())

    return {"analysis_id": analysis_id, "status": "queued"}


@router.get("/analysis/{analysis_id}/status", response_model=AnalysisStatus)
async def get_analysis_status(analysis_id: str) -> AnalysisStatus:
    from sqlalchemy import select

    from app.persistence.models import AnalysisJobORM

    async with session_scope() as session:
        result = await session.execute(
            select(AnalysisJobORM).where(AnalysisJobORM.analysis_id == analysis_id)
        )
        orm = result.scalar_one_or_none()

    if orm is None:
        raise AnalysisNotFoundError(f"analysis not found: {analysis_id}", analysis_id=analysis_id)

    return AnalysisStatus(
        analysis_id=orm.analysis_id,
        status=orm.status,
        current_node=orm.current_node,
        progress_percent=(
            100 if orm.status in ("completed", "failed", "partial") else orm.progress_percent
        ),
        started_at=orm.started_at,
        completed_at=orm.completed_at,
        error=orm.error,
    )
