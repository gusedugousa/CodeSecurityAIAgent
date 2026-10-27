"""Domain-specific tracing helpers built on top of app.core.telemetry's tracer."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

from app.core.telemetry import get_tracer

_ATTR_KEYS = (
    "repo_url",
    "local_repo_path",
    "local_path",
    "branch",
    "commit_sha",
    "agent_name",
    "node_name",
    "tool_name",
    "model_provider",
    "model_name",
    "duration_ms",
    "findings_count",
)


def repo_identifier(**attrs: Any) -> str | None:
    """Resolve a single filterable repo identity: repo_url wins, else the local
    path (post-ingestion local_repo_path, else the raw request local_path) - so
    both remote (repo_url) and local-path scans are identifiable in traces.
    """
    return attrs.get("repo_url") or attrs.get("local_repo_path") or attrs.get("local_path")


def repo_attrs(state: dict[str, Any]) -> dict[str, Any]:
    """Extract the repo-identity kwargs every span call site should pass, straight
    from the LangGraph state dict every agent already has on hand."""
    return {
        "repo_url": state.get("repo_url"),
        "local_repo_path": state.get("local_repo_path"),
        "local_path": state.get("local_path"),
        "branch": state.get("branch"),
        "commit_sha": state.get("commit_sha"),
    }


@contextmanager
def analysis_span(name: str, analysis_id: str, **attrs: Any) -> Iterator[trace.Span]:
    # Resolved lazily (not at module import time): app.main imports this module's
    # callers (routers -> agents) before FastAPI's lifespan runs configure_telemetry(),
    # so a module-level get_tracer() would permanently capture the pre-configured
    # no-op TracerProvider instead of the real one installed at startup.
    tracer = get_tracer(__name__)
    span_name = f"analysis.{name}"
    with tracer.start_as_current_span(span_name) as span:
        span.set_attribute("analysis_id", analysis_id)
        repo = repo_identifier(**attrs)
        if repo is not None:
            span.set_attribute("repo", repo)
        for key in _ATTR_KEYS:
            value = attrs.get(key)
            if value is not None:
                span.set_attribute(key, value)
        try:
            yield span
        except Exception as exc:
            span.record_exception(exc)
            span.set_status(Status(StatusCode.ERROR, str(exc)))
            raise


@contextmanager
def agent_node_span(node_name: str, analysis_id: str, **attrs: Any) -> Iterator[trace.Span]:
    with analysis_span("agent_node", analysis_id, node_name=node_name, **attrs) as span:
        yield span


@contextmanager
def tool_execution_span(tool_name: str, analysis_id: str, **attrs: Any) -> Iterator[trace.Span]:
    with analysis_span("tool_execution", analysis_id, tool_name=tool_name, **attrs) as span:
        yield span


@contextmanager
def model_call_span(
    role: str, model_name: str, analysis_id: str, **attrs: Any
) -> Iterator[trace.Span]:
    with analysis_span(
        "model_call", analysis_id, model_name=model_name, **attrs
    ) as span:
        span.set_attribute("role", role)
        yield span
