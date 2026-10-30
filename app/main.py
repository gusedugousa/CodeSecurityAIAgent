"""FastAPI application entry point: wires config, telemetry, DB init, and routers."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.api import routes_analysis, routes_findings, routes_reports
from app.core.config import get_settings
from app.core.errors import PlatformError
from app.core.logging import configure_logging, get_logger
from app.core.telemetry import configure_telemetry, instrument_fastapi
from app.persistence.db import get_engine, init_db

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging(settings.log_level)
    configure_telemetry(settings)
    await init_db(get_engine())
    logger.info("startup_complete", environment=settings.environment)
    yield
    logger.info("shutdown")


app = FastAPI(
    title="Governed AI Code Security",
    description="AI Agentic Code Security Analysis Platform (MVP)",
    version="0.1.2",
    lifespan=lifespan,
)

instrument_fastapi(app)

app.include_router(routes_analysis.router, prefix="/api/v1")
app.include_router(routes_findings.router, prefix="/api/v1")
app.include_router(routes_reports.router, prefix="/api/v1")


@app.exception_handler(PlatformError)
async def platform_error_handler(request: Request, exc: PlatformError) -> JSONResponse:
    status_code = {
        "analysis_not_found": 404,
        "configuration_error": 500,
        "repository_ingestion_error": 400,
    }.get(exc.code, 500)
    return JSONResponse(status_code=status_code, content={"code": exc.code, "message": exc.message})


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.get("/ready")
async def ready() -> dict:
    # Readiness only checks the DB is reachable; tool/model availability is per-analysis,
    # not a startup precondition (spec: platform must be useful with only a tool subset).
    try:
        engine = get_engine()
        async with engine.connect():
            pass
    except Exception as exc:
        return JSONResponse(status_code=503, content={"status": "not_ready", "error": str(exc)})
    return {"status": "ready"}
