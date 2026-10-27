"""OpenTelemetry instruments for the analysis platform, created once as module singletons."""

from __future__ import annotations

from opentelemetry.metrics import Counter, Histogram

from app.core.telemetry import get_meter

_meter = get_meter(__name__)

analysis_jobs_total: Counter = _meter.create_counter(
    "analysis_jobs_total",
    unit="1",
    description="Total number of analysis jobs started",
)

analysis_jobs_failed_total: Counter = _meter.create_counter(
    "analysis_jobs_failed_total",
    unit="1",
    description="Total number of analysis jobs that failed",
)

analysis_duration_seconds: Histogram = _meter.create_histogram(
    "analysis_duration_seconds",
    unit="s",
    description="Duration of a full analysis job",
)

agent_node_duration_seconds: Histogram = _meter.create_histogram(
    "agent_node_duration_seconds",
    unit="s",
    description="Duration of a single agent node execution",
)

tool_execution_duration_seconds: Histogram = _meter.create_histogram(
    "tool_execution_duration_seconds",
    unit="s",
    description="Duration of a single security tool execution",
)

findings_total: Counter = _meter.create_counter(
    "findings_total",
    unit="1",
    description="Total number of findings produced",
)

findings_by_severity: Counter = _meter.create_counter(
    "findings_by_severity",
    unit="1",
    description="Total number of findings produced, by severity",
)

llm_calls_total: Counter = _meter.create_counter(
    "llm_calls_total",
    unit="1",
    description="Total number of LLM calls made",
)

llm_tokens_total: Counter = _meter.create_counter(
    "llm_tokens_total",
    unit="1",
    description="Total number of LLM tokens consumed, by token_type (input|output)",
)

llm_cost_estimate_total: Counter = _meter.create_counter(
    "llm_cost_estimate_total",
    unit="USD",
    description="Estimated total USD cost of LLM calls",
)


def record_analysis_started() -> None:
    analysis_jobs_total.add(1)


def record_analysis_completed(duration_seconds: float, status: str) -> None:
    analysis_duration_seconds.record(duration_seconds, {"status": status})
    if status == "failed":
        analysis_jobs_failed_total.add(1)


def record_agent_node_duration(node_name: str, duration_seconds: float) -> None:
    agent_node_duration_seconds.record(duration_seconds, {"node_name": node_name})


def record_tool_execution(tool_name: str, duration_seconds: float) -> None:
    tool_execution_duration_seconds.record(duration_seconds, {"tool_name": tool_name})


def record_findings(count: int, severity_counts: dict[str, int]) -> None:
    findings_total.add(count)
    for severity, severity_count in severity_counts.items():
        if severity_count:
            findings_by_severity.add(severity_count, {"severity": severity})


def record_llm_call(
    role: str,
    model_name: str,
    tokens_input: int | None,
    tokens_output: int | None,
    cost_estimate: float | None,
) -> None:
    attributes = {"role": role, "model_name": model_name}
    llm_calls_total.add(1, attributes)
    if tokens_input:
        llm_tokens_total.add(tokens_input, {**attributes, "token_type": "input"})
    if tokens_output:
        llm_tokens_total.add(tokens_output, {**attributes, "token_type": "output"})
    if cost_estimate:
        llm_cost_estimate_total.add(cost_estimate, attributes)
