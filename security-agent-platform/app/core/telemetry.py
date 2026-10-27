"""OpenTelemetry bootstrap: tracer/meter providers, exporters, FastAPI instrumentation.

Safe to call `configure_telemetry` more than once (idempotent) since the FastAPI
app module that owns startup is built by another layer and may invoke this
during import-time experimentation, tests, or reloads.
"""

from __future__ import annotations

from typing import Any

from opentelemetry import metrics, trace
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SimpleSpanProcessor,
)

from app.core.logging import get_logger

_logger = get_logger(__name__)

_configured: bool = False


def configure_telemetry(settings: Any) -> None:
    global _configured
    if _configured:
        return

    observability = settings.observability
    service_name: str = observability.get("service_name", "security-agent-platform")
    service_version: str = observability.get("service_version", "0.0.0")
    environment: str = getattr(settings, "environment", "local")

    resource = Resource.create(
        {
            "service.name": service_name,
            "service.version": service_version,
            "deployment.environment": environment,
        }
    )

    tracer_provider = TracerProvider(resource=resource)
    meter_provider: MeterProvider | None = None

    traces_enabled: bool = observability.get("traces_enabled", True)
    metrics_enabled: bool = observability.get("metrics_enabled", True)
    console_fallback_enabled: bool = observability.get("console_fallback_enabled", False)
    otel_endpoint: str = observability.get("otel_endpoint", "http://localhost:4317")
    metrics_export_interval_ms: int = observability.get("metrics_export_interval_ms", 5000)

    if traces_enabled:
        try:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                OTLPSpanExporter,
            )

            otlp_span_exporter = OTLPSpanExporter(endpoint=otel_endpoint)
            tracer_provider.add_span_processor(BatchSpanProcessor(otlp_span_exporter))
        except Exception as exc:
            # The otel-collector may not be up yet (e.g. bare `make run` without
            # docker-compose) — never let telemetry setup prevent app startup.
            _logger.warning(
                "otlp_span_exporter_setup_failed", error=str(exc), otel_endpoint=otel_endpoint
            )

        if console_fallback_enabled and environment == "local":
            # Console exporter is dev-only: it prints every span to stdout, which
            # would be noisy/expensive in production.
            tracer_provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))

    if metrics_enabled:
        try:
            from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
                OTLPMetricExporter,
            )
            from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader

            otlp_metric_exporter = OTLPMetricExporter(endpoint=otel_endpoint)
            metric_reader = PeriodicExportingMetricReader(
                otlp_metric_exporter,
                export_interval_millis=metrics_export_interval_ms,
            )
            meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
        except Exception as exc:
            _logger.warning(
                "otlp_metric_exporter_setup_failed", error=str(exc), otel_endpoint=otel_endpoint
            )
            meter_provider = MeterProvider(resource=resource)
    else:
        meter_provider = MeterProvider(resource=resource)

    trace.set_tracer_provider(tracer_provider)
    metrics.set_meter_provider(meter_provider)

    _configured = True


def instrument_fastapi(app: Any) -> None:
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

    FastAPIInstrumentor.instrument_app(app)


def get_tracer(name: str) -> trace.Tracer:
    return trace.get_tracer(name)


def get_meter(name: str) -> metrics.Meter:
    return metrics.get_meter(name)


# Future cloud exporters (Azure Monitor, AWS CloudWatch, Datadog) are documented
# as intent in configs/observability.yaml (future_cloud_exporters) and
# docs/observability.md, but are not wired into this MVP.
