# Extension Points

Practical, file-level instructions for extending the platform. Every extension described here
follows a pattern already used somewhere in the MVP — none require touching more than 1-2 layers.

## Add a new agent

1. Create `app/agents/your_agent.py` with a class extending `BaseAgent`
   (`app/agents/base.py`): set `name: str`, implement `async def run(self, state: dict) -> dict`.
   Never raise for recoverable failures — append to `state["warnings"]` or `state["errors"]` and
   return the state; only truly fatal conditions should set `state["fatal_error"] = True`.
2. If the agent runs security tools, instantiate the relevant `ToolAdapter`s and call
   `app.tools.runner.run_all(adapters, state["local_repo_path"], state["tools_config"])`, exactly
   as `app/agents/sast_agent.py` does.
3. If the agent calls an LLM, resolve a model via
   `ModelRouter(state["models_config"]).resolve(role, state["model_profile"])`, then call
   `LiteLLMModelClient(state["models_config"], state["mock_mode"]).call(...)`, wrapped in
   `model_call_span(...)` and followed by `log_model_call(...)`/`record_llm_call(...)`.
4. Wire it into the graph in `app/orchestration/graph.py`: add a node function
   (`async def _your_node(state): return await YourAgent().execute_with_telemetry(state)`),
   `graph.add_node("your_node", _your_node)`, and add edges connecting it into the flow.
5. If it introduces new state, add the field to `AnalysisState` in
   `app/orchestration/state.py` (TypedDict, `total=False`) and initialize it in
   `create_initial_state()`.

The four `app/agents/future_*.py` stubs (code understanding, IaC/cloud security, threat
modeling, validation/exploitability) are ready-made examples of step 1 with an empty `run()` —
copy one as a starting point.

## Add a new tool

1. Create `app/tools/your_tool.py` with a class extending `ToolAdapter`
   (`app/tools/base.py`): set `name` (must match the tool's CLI binary name, or override
   `is_available()`/`build_command()` if the binary name differs from the config key — see
   `app/tools/pip_audit.py` for an example where `name="pip_audit"` but the binary is
   `pip-audit`), `category`, implement `build_command()` and `parse_output()`.
2. `parse_output()` must never raise: wrap JSON parsing in try/except, and on failure fall back
   to `([], {"raw_stdout": stdout, "raw_stderr": stderr, "parse_error": "..."})` — see any
   existing adapter (`app/tools/semgrep.py`) for the pattern.
3. Add an entry to `configs/tools.yaml` under `tools:` with `command`, `args`, `timeout_seconds`,
   `output_parser`, `category`, and `severity_mapping`.
4. Instantiate the adapter in whichever agent should run it (`SASTAgent`, `SecretsAgent`, or
   `DependencyAgent`), passing it into `run_all(...)` alongside the existing adapters.
5. If the tool is genuinely unavailable on most dev machines (a placeholder, like
   `app/tools/docker_tool.py`), set `enabled: false` in `configs/tools.yaml` and document why.

## Add a new model provider

Because every LLM call goes through LiteLLM, adding a provider is almost entirely configuration:

1. Confirm LiteLLM supports the provider (it supports OpenAI, Azure OpenAI, Anthropic, Gemini,
   Ollama, and dozens more out of the box via a `provider/model` name).
2. Add a new profile (or extend an existing one) in `configs/models.yaml` under `profiles:`,
   mapping each role (`coordinator_model`, `analysis_model`, `remediation_model`,
   `reporting_model`, `cheap_classifier_model`) to the new `provider/model` string.
3. Add an entry to `cost_table_per_1k_tokens` for accurate `cost_estimate` telemetry (optional —
   defaults to `0.0` if omitted).
4. Add any required credential env var to `.env.example` (never commit a real value) and read it
   in `app/core/config.py::ProviderEnvSettings` if a new env var name is needed — the key value
   itself must never be exposed on the composed `Settings` object, only a boolean presence flag
   in `Settings.provider_credentials_present`.
5. No code changes are needed in `app/models/litellm_client.py` — it passes the resolved model
   name straight through to `litellm.acompletion()`.

## Add a new report format

1. Create `app/reports/your_format.py` with `generate_your_format_report(analysis_id, findings,
   repository_metadata, ..., generated_at=None) -> <dict|str>` and
   `write_your_format_report(report, output_path) -> int` (bytes written), following the shape of
   `app/reports/json_report.py`. Use `app/reports/_shared.py::as_dict()` to accept either dicts
   or Pydantic models as input, and `severity_sort_key()` for consistent ordering.
2. Add a `report_type` value to the `Literal` in `app/api/schemas.py::ReportArtifact` and to the
   `_MEDIA_TYPES` dict in `app/api/routes_reports.py`.
3. Add a `GET /api/v1/analysis/{analysis_id}/reports/your_format` endpoint in
   `app/api/routes_reports.py`, following the existing three.
4. Call your generator/writer functions alongside the existing three in
   `app/api/routes_analysis.py::_run_analysis_job()`, and persist a `ReportArtifact` row via
   `ReportArtifactRepository.create()`.

## Add a new observability exporter

1. All exporting happens at the OpenTelemetry Collector, not in application code. Add a new
   exporter block to `infra/otel-collector-config.yaml` (e.g. `awsemf` or `azuremonitor` from
   `opentelemetry-collector-contrib`), configure its credentials via environment variables passed
   into the `otel-collector` service in `docker-compose.yml`, and reference the exporter name
   from the relevant `service.pipelines.<traces|metrics|logs>.exporters` list.
2. No changes are needed to `app/core/telemetry.py` — the app only ever talks OTLP to the
   collector; it has no cloud-specific exporter code and should not gain any (that would
   reintroduce the vendor lock-in the architecture explicitly avoids).
3. See `configs/observability.yaml`'s `future_cloud_exporters` section and
   `docs/observability.md` for the intended shape of Azure Monitor / AWS CloudWatch / Datadog
   support.

## Add a new MCP integration

See `docs/mcp_strategy.md` — implement a concrete `MCPToolAdapter` subclass, register it in
`app/mcp/registry.py::MCPRegistry` in place of the corresponding placeholder from
`app/mcp/placeholders.py`, and set the matching `MCP_*_SERVER_URL` environment variable.

## Wire up authentication, authorization, or rate limiting

`app/core/security.py` defines `AuthenticationPlaceholder`, `AuthorizationPlaceholder`, and
`RateLimiterPlaceholder` — each raises `NotImplementedError` today. To implement:

1. Replace `AuthenticationPlaceholder.authenticate()` with a real provider integration (OAuth2/
   OIDC/SSO), returning a populated `AuthContext`.
2. Replace `AuthorizationPlaceholder.authorize()` with a real policy check (RBAC/ABAC).
3. Replace `RateLimiterPlaceholder.check()` with a real backend (Redis token bucket is the
   natural choice given `app.persistence` already assumes Redis is available in compose).
4. Wire these as FastAPI dependencies on the routers in `app/api/routes_analysis.py` and friends
   — none of the MVP routes currently depend on them, so adding the `Depends(...)` wiring is the
   only application-layer change required.
