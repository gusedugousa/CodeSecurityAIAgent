"""Semantically named structured log events, correlated by analysis_id.

Most functions here log only counts/metadata, never raw content. The
`*_raw` variants are the deliberate exception: they exist for local
debugging/inspection of exactly what was sent to/received from a tool or
model, always passed through redact_secrets first (defense in depth on
top of the redaction already applied before tool/model invocation).

Every function also accepts `repo`, the resolved single-value repo identity
(see app.observability.tracing.repo_identifier) - bound alongside analysis_id
so Promtail can promote it to a Loki label, mirroring the `repo` span
attribute already set on every trace via app.observability.tracing.
"""

from __future__ import annotations

from app.core.logging import get_logger
from app.core.security import redact_secrets

_logger = get_logger(__name__)

_MAX_RAW_LOG_CHARS = 8000  # keep individual log lines bounded; full detail still in Loki via multiple lines if needed


def _truncate(text: str | None) -> str | None:
    if text is None:
        return None
    redacted = redact_secrets(text)
    if len(redacted) > _MAX_RAW_LOG_CHARS:
        return redacted[:_MAX_RAW_LOG_CHARS] + f"...[truncated, {len(redacted)} chars total]"
    return redacted


def log_analysis_started(
    analysis_id: str, repo_url: str | None, branch: str | None, repo: str | None = None
) -> None:
    _logger.bind(analysis_id=analysis_id, repo=repo).info(
        "analysis_started", repo_url=repo_url, branch=branch
    )


def log_analysis_completed(
    analysis_id: str,
    status: str,
    duration_ms: float,
    findings_count: int,
    repo: str | None = None,
) -> None:
    _logger.bind(analysis_id=analysis_id, repo=repo).info(
        "analysis_completed",
        status=status,
        duration_ms=duration_ms,
        findings_count=findings_count,
    )


def log_agent_node_started(analysis_id: str, node_name: str, repo: str | None = None) -> None:
    _logger.bind(analysis_id=analysis_id, repo=repo).info(
        "agent_node_started", node_name=node_name
    )


def log_agent_node_completed(
    analysis_id: str,
    node_name: str,
    status: str,
    duration_ms: float,
    warnings: list[str] | None = None,
    repo: str | None = None,
) -> None:
    _logger.bind(analysis_id=analysis_id, repo=repo).info(
        "agent_node_completed",
        node_name=node_name,
        status=status,
        duration_ms=duration_ms,
        warnings=warnings or [],
    )


def log_tool_execution(
    analysis_id: str,
    tool_name: str,
    available: bool,
    exit_code: int | None,
    duration_ms: float,
    findings_count: int,
    repo: str | None = None,
) -> None:
    _logger.bind(analysis_id=analysis_id, repo=repo).info(
        "tool_execution",
        tool_name=tool_name,
        available=available,
        exit_code=exit_code,
        duration_ms=duration_ms,
        findings_count=findings_count,
    )


def log_model_call(
    analysis_id: str,
    role: str,
    provider: str,
    model_name: str,
    token_count_input: int | None,
    token_count_output: int | None,
    cost_estimate: float | None,
    duration_ms: float,
    mock: bool,
    repo: str | None = None,
) -> None:
    _logger.bind(analysis_id=analysis_id, repo=repo).info(
        "model_call",
        role=role,
        provider=provider,
        model_name=model_name,
        token_count_input=token_count_input,
        token_count_output=token_count_output,
        cost_estimate=cost_estimate,
        duration_ms=duration_ms,
        mock=mock,
    )


def log_error(
    analysis_id: str,
    component: str,
    message: str,
    exc: Exception | None = None,
    repo: str | None = None,
) -> None:
    _logger.bind(analysis_id=analysis_id, repo=repo).error(
        "error",
        component=component,
        message=message,
        error_type=type(exc).__name__ if exc is not None else None,
    )


def log_tool_execution_raw(
    analysis_id: str,
    tool_name: str,
    command: str | None,
    stdout: str | None,
    stderr: str | None,
    repo: str | None = None,
) -> None:
    _logger.bind(analysis_id=analysis_id, repo=repo).info(
        "tool_execution_raw",
        tool_name=tool_name,
        command=command,
        stdout=_truncate(stdout),
        stderr=_truncate(stderr),
    )


def log_model_call_raw(
    analysis_id: str,
    role: str,
    model_name: str,
    prompt: str | None,
    response: str | None,
    repo: str | None = None,
) -> None:
    _logger.bind(analysis_id=analysis_id, repo=repo).info(
        "model_call_raw",
        role=role,
        model_name=model_name,
        prompt=_truncate(prompt),
        response=_truncate(response),
    )
