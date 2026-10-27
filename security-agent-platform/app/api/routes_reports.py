"""Report retrieval endpoints: JSON, Markdown, SARIF."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse

from app.core.errors import AnalysisNotFoundError, ReportGenerationError
from app.persistence.db import session_scope
from app.persistence.repositories import AnalysisJobRepository, ReportArtifactRepository

router = APIRouter(tags=["reports"])

_MEDIA_TYPES = {
    "json": "application/json",
    "markdown": "text/markdown",
    "sarif": "application/sarif+json",
    "csv": "text/csv",
    "csv_deduplicated": "text/csv",
}


async def _get_artifact(analysis_id: str, report_type: str):
    async with session_scope() as session:
        job = await AnalysisJobRepository(session).get(analysis_id)
        if job is None:
            raise AnalysisNotFoundError(
                f"analysis not found: {analysis_id}", analysis_id=analysis_id
            )
        artifact = await ReportArtifactRepository(session).get_latest(analysis_id, report_type)

    if artifact is None:
        raise ReportGenerationError(
            f"{report_type} report not yet available for analysis {analysis_id} "
            "(analysis may still be running)",
            analysis_id=analysis_id,
            report_type=report_type,
        )
    if not Path(artifact.path).is_file():
        raise ReportGenerationError(
            f"{report_type} report artifact record exists but file is missing on disk",
            analysis_id=analysis_id,
            report_type=report_type,
        )
    return artifact


@router.get("/analysis/{analysis_id}/reports/json")
async def get_json_report(analysis_id: str) -> JSONResponse:
    artifact = await _get_artifact(analysis_id, "json")
    return FileResponse(artifact.path, media_type=_MEDIA_TYPES["json"])


@router.get("/analysis/{analysis_id}/reports/markdown")
async def get_markdown_report(analysis_id: str) -> PlainTextResponse:
    artifact = await _get_artifact(analysis_id, "markdown")
    return FileResponse(artifact.path, media_type=_MEDIA_TYPES["markdown"])


@router.get("/analysis/{analysis_id}/reports/sarif")
async def get_sarif_report(analysis_id: str) -> JSONResponse:
    artifact = await _get_artifact(analysis_id, "sarif")
    return FileResponse(artifact.path, media_type=_MEDIA_TYPES["sarif"])


@router.get("/analysis/{analysis_id}/reports/csv")
async def get_csv_report(analysis_id: str) -> PlainTextResponse:
    artifact = await _get_artifact(analysis_id, "csv")
    return FileResponse(
        artifact.path,
        media_type=_MEDIA_TYPES["csv"],
        filename=f"{analysis_id}-findings.csv",
    )


@router.get("/analysis/{analysis_id}/reports/csv-deduplicated")
async def get_csv_deduplicated_report(analysis_id: str) -> PlainTextResponse:
    artifact = await _get_artifact(analysis_id, "csv_deduplicated")
    return FileResponse(
        artifact.path,
        media_type=_MEDIA_TYPES["csv_deduplicated"],
        filename=f"{analysis_id}-findings-deduplicated.csv",
    )
