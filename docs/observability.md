# Observability

## Why OpenTelemetry

OpenTelemetry (OTel) is used exclusively — no vendor SDK is imported directly by application
code — so the platform can export to any backend (local Grafana stack today, Azure Monitor or
AWS CloudWatch later) by changing collector configuration, not application code.

## Traces

`app/core/telemetry.py::configure_telemetry()` sets up a `TracerProvider` at startup, exporting
via OTLP gRPC to the endpoint in `configs/observability.yaml` (`otel_endpoint`, overridable via
`OTEL_EXPORTER_OTLP_ENDPOINT`). FastAPI request spans are added automatically via
`FastAPIInstrumentor` (`instrument_fastapi()` in `app/main.py`).

On top of that, `app/observability/tracing.py` defines three domain-specific span helpers, all
built on the same underlying `analysis_span()`:

- `agent_node_span(node_name, analysis_id, ...)` — one span per LangGraph node execution.
- `tool_execution_span(tool_name, analysis_id, ...)` — one span per security tool subprocess run.
- `model_call_span(role, model_name, analysis_id, ...)` — one span per LLM call.

Every span carries `analysis_id` as an attribute, so a single trace can be filtered end-to-end in
Tempo/Jaeger by that correlation ID, and cross-referenced against logs in Loki using the same ID.
Span attributes follow the spec's required set where applicable to that span type: repo_url,
local_repo_path, local_path, branch, commit_sha, agent_name, node_name, tool_name, model_provider,
model_name, duration_ms, findings_count.

Every span in an analysis's tree — every `agent_node`, `tool_execution`, and `model_call` span,
not just the first one — also carries a single derived `repo` attribute
(`app.observability.tracing.repo_identifier()`): `repo_url` if the scan was against a remote
repo, else the resolved `local_repo_path`, else the raw request `local_path`. This is the
recommended field to filter or group by in Tempo/Grafana Explore (e.g.
`{repo="/scan-targets/my-repo"}`) when comparing runs across different repos, since
`analysis_id` alone doesn't tell you which repo a given trace belongs to.

If the OTLP collector is unreachable (e.g. running `make run` without `docker-compose up`),
`configure_telemetry()` catches the exporter setup failure, logs a warning, and the app starts
normally — spans are simply dropped rather than blocking startup. In `environment: local`, a
console span exporter is also attached so traces are visible without any collector running.

## Metrics

`app/observability/metrics.py` defines the spec-required OTel instruments as module-level
singletons (created once, never recreated per-call, per OTel best practice):

| Metric | Type | Key attributes |
|---|---|---|
| `analysis_jobs_total` | Counter | — |
| `analysis_jobs_failed_total` | Counter | — |
| `analysis_duration_seconds` | Histogram | status |
| `agent_node_duration_seconds` | Histogram | node_name |
| `tool_execution_duration_seconds` | Histogram | tool_name |
| `findings_total` | Counter | — |
| `findings_by_severity` | Counter | severity |
| `llm_calls_total` | Counter | role, model_name |
| `llm_tokens_total` | Counter | token_type (input/output) |
| `llm_cost_estimate_total` | Counter | — |

These are recorded from `app/agents/base.py`'s `execute_with_telemetry()` wrapper and from each
agent's tool/model call sites — every agent gets this instrumentation for free by extending
`BaseAgent`, rather than each agent hand-rolling metric calls.

## Logs

`app/core/logging.py::configure_logging()` configures `structlog` to emit single-line JSON to
stdout, with every log call passing through a redaction processor
(`app/core/security.py::redact_dict`) before serialization — any bound context key that looks
secret-shaped (`password`, `token`, `key`, `secret`, `credential`) is replaced with `[REDACTED]`
regardless of call site. `app/observability/events.py` provides semantically named event
functions (`log_analysis_started`, `log_agent_node_completed`, `log_tool_execution`,
`log_model_call`, `log_error`, ...) that bind `analysis_id` into every emitted event, so logs for
a single analysis can be grepped/filtered by that one field across the whole run.

## Local stack

`docker-compose.yml` runs the full observability stack alongside the app:

- **otel-collector** (`infra/otel-collector-config.yaml`) receives OTLP traces/metrics/logs from
  the app and fans them out to Tempo (traces) and a Prometheus-scrapeable endpoint (metrics).
- **prometheus** (`infra/prometheus.yml`) scrapes the collector's Prometheus exporter endpoint.
- **tempo** (`infra/tempo-config.yaml`) stores traces, queryable from Grafana.
- **loki** (`infra/loki-config.yaml`) is available as a log aggregation backend (the app emits
  JSON to stdout; a log shipper such as Promtail, not included in the MVP compose file, would
  forward container stdout into Loki in a fuller setup).
- **grafana** auto-provisions all three datasources (`infra/grafana/provisioning/datasources/`)
  and the MVP dashboard (`infra/grafana/dashboards/mvp-dashboard.json`), reachable at
  `http://localhost:3000` (default local-only credentials `admin`/`admin`, anonymous viewer
  access enabled for convenience).

The MVP dashboard shows: total analyses, error rate, average analysis duration, findings by
severity, tool execution failures, LLM call volume, token usage, and estimated LLM cost — all
sourced from the metrics table above.

## Exporting to a cloud backend later

Because everything goes through the OTel Collector, adding a cloud exporter is a collector
config change, not an application change: add an `azuremonitor` or `awscloudwatch` (via the
`awsemf`/`awsxray` exporters in `opentelemetry-collector-contrib`) exporter to
`infra/otel-collector-config.yaml`'s `exporters` section and reference it from the relevant
pipeline. `configs/observability.yaml`'s `future_cloud_exporters` section documents this intent
without wiring credentials into the MVP — no cloud SDK or credential handling exists in
application code today.
