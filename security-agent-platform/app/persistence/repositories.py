"""Repository pattern classes wrapping CRUD operations over the ORM models."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import AnalysisJob, Finding, ReportArtifact, SeveritySummary, ToolExecutionResult
from app.persistence.models import (
    AnalysisJobORM,
    FindingORM,
    ReportArtifactORM,
    ToolExecutionORM,
    analysis_job_orm_to_pydantic,
    analysis_job_pydantic_to_orm,
    finding_orm_to_pydantic,
    finding_pydantic_to_orm,
    report_artifact_orm_to_pydantic,
    report_artifact_pydantic_to_orm,
    severity_summary_from_findings,
    tool_execution_orm_to_pydantic,
    tool_execution_pydantic_to_orm,
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AnalysisJobRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, job: AnalysisJob) -> None:
        self._session.add(analysis_job_pydantic_to_orm(job))
        await self._session.commit()

    async def get(self, analysis_id: str) -> AnalysisJob | None:
        result = await self._session.execute(
            select(AnalysisJobORM).where(AnalysisJobORM.analysis_id == analysis_id)
        )
        orm = result.scalar_one_or_none()
        return analysis_job_orm_to_pydantic(orm) if orm is not None else None

    async def update_status(
        self,
        analysis_id: str,
        status: str,
        current_node: str | None = None,
        progress_percent: int | None = None,
        error: str | None = None,
    ) -> None:
        result = await self._session.execute(
            select(AnalysisJobORM).where(AnalysisJobORM.analysis_id == analysis_id)
        )
        orm = result.scalar_one_or_none()
        if orm is None:
            return
        orm.status = status
        if current_node is not None:
            orm.current_node = current_node
        if progress_percent is not None:
            orm.progress_percent = progress_percent
        if error is not None:
            orm.error = error
        orm.updated_at = _utcnow()
        await self._session.commit()

    async def mark_started(self, analysis_id: str) -> None:
        result = await self._session.execute(
            select(AnalysisJobORM).where(AnalysisJobORM.analysis_id == analysis_id)
        )
        orm = result.scalar_one_or_none()
        if orm is None:
            return
        orm.started_at = _utcnow()
        orm.status = "running"
        orm.updated_at = _utcnow()
        await self._session.commit()

    async def mark_completed(self, analysis_id: str, status: str) -> None:
        result = await self._session.execute(
            select(AnalysisJobORM).where(AnalysisJobORM.analysis_id == analysis_id)
        )
        orm = result.scalar_one_or_none()
        if orm is None:
            return
        orm.completed_at = _utcnow()
        orm.status = status
        orm.updated_at = _utcnow()
        await self._session.commit()


class FindingRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def bulk_create(self, findings: list[Finding], analysis_id: str) -> None:
        for finding in findings:
            self._session.add(finding_pydantic_to_orm(finding, analysis_id))
        await self._session.commit()

    async def list_by_analysis(self, analysis_id: str) -> list[Finding]:
        result = await self._session.execute(
            select(FindingORM).where(FindingORM.analysis_id == analysis_id)
        )
        return [finding_orm_to_pydantic(orm) for orm in result.scalars().all()]

    async def severity_summary(self, analysis_id: str) -> SeveritySummary:
        findings = await self.list_by_analysis(analysis_id)
        return severity_summary_from_findings(findings)


class ToolExecutionRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def bulk_create(self, results: list[ToolExecutionResult], analysis_id: str) -> None:
        for result in results:
            self._session.add(tool_execution_pydantic_to_orm(result, analysis_id))
        await self._session.commit()

    async def list_by_analysis(self, analysis_id: str) -> list[ToolExecutionResult]:
        result = await self._session.execute(
            select(ToolExecutionORM).where(ToolExecutionORM.analysis_id == analysis_id)
        )
        return [tool_execution_orm_to_pydantic(orm) for orm in result.scalars().all()]


class ReportArtifactRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, artifact: ReportArtifact) -> None:
        self._session.add(report_artifact_pydantic_to_orm(artifact))
        await self._session.commit()

    async def get_latest(self, analysis_id: str, report_type: str) -> ReportArtifact | None:
        result = await self._session.execute(
            select(ReportArtifactORM)
            .where(
                ReportArtifactORM.analysis_id == analysis_id,
                ReportArtifactORM.report_type == report_type,
            )
            .order_by(ReportArtifactORM.generated_at.desc())
            .limit(1)
        )
        orm = result.scalar_one_or_none()
        return report_artifact_orm_to_pydantic(orm) if orm is not None else None
