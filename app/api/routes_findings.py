"""Findings retrieval endpoint."""

from __future__ import annotations

from fastapi import APIRouter

from app.core.errors import AnalysisNotFoundError
from app.persistence.db import session_scope
from app.persistence.repositories import AnalysisJobRepository, FindingRepository

router = APIRouter(tags=["findings"])


@router.get("/analysis/{analysis_id}/findings")
async def get_findings(analysis_id: str) -> dict:
    async with session_scope() as session:
        job = await AnalysisJobRepository(session).get(analysis_id)
        if job is None:
            raise AnalysisNotFoundError(
                f"analysis not found: {analysis_id}", analysis_id=analysis_id
            )
        findings = await FindingRepository(session).list_by_analysis(analysis_id)
        severity_summary = await FindingRepository(session).severity_summary(analysis_id)

    return {
        "analysis_id": analysis_id,
        "findings": [f.model_dump(mode="json") for f in findings],
        "severity_summary": severity_summary.model_dump(mode="json"),
    }
