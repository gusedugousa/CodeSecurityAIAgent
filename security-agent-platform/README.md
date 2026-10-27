# Security Agent Platform (MVP)

An AI-agentic code security analysis platform: a FastAPI service that runs a LangGraph
coordinator + subagent workflow over a source repository, executing security scanners
(Semgrep, Bandit, Gitleaks, TruffleHog, pip-audit, OSV-Scanner, Trivy, Checkov), normalizing
their output into typed findings, optionally enriching/remediating findings with an LLM (via
LiteLLM, provider-agnostic), and producing JSON / Markdown / SARIF-like reports.

Runs fully offline with zero API keys via a deterministic **mock model mode** — see
[Model Strategy](docs/model_strategy.md).

## Architecture

See [docs/architecture.md](docs/architecture.md) for the full design, including why LangGraph is
the orchestrator, LangChain's limited role, the LiteLLM model gateway, the MCP-ready tool layer,
and the observability architecture. See [docs/mvp_architecture.drawio](docs/mvp_architecture.drawio)
and [docs/final_architecture.drawio](docs/final_architecture.drawio) for diagrams (open with
[draw.io](https://app.diagrams.net)).

```
Client -> FastAPI Gateway -> Coordinator Agent -> LangGraph:
  repo_ingestion -> sast -> secrets -> dependency -> remediation -> report
-> Persistence (SQLite/Postgres) -> Reports (JSON/Markdown/SARIF)
```

## Quick start (Docker)

```bash
cp .env.example .env
make docker-up      # starts app, postgres, redis, otel-collector, prometheus, grafana, loki, tempo
make analyze-sample  # submits the bundled vulnerable sample repo for analysis
```

Grafana: http://localhost:3001 (admin/admin, anonymous viewer access enabled). Prometheus:
http://localhost:9090. The app: http://localhost:8001 (interactive API docs at `/docs`).

```bash
make docker-down
```

## Quick start (local, no Docker)

```bash
python3 -m venv .venv && source .venv/bin/activate
make install
make run    # uvicorn on http://localhost:8000, SQLite storage, mock model mode by default
```

In another terminal (note: `make analyze-sample` targets port 8001, the Docker-published port —
for the local no-Docker server on 8000, use the manual curl command below instead):

```bash
curl -X POST http://localhost:8000/api/v1/analysis \
  -H "Content-Type: application/json" \
  -d '{
    "local_path": "tests/fixtures/sample_vulnerable_repo",
    "analysis_profile": "mvp-default",
    "model_profile": "default",
    "enable_remediation": true
  }'
# => {"analysis_id": "...", "status": "queued"}

curl http://localhost:8000/api/v1/analysis/<analysis_id>/status
curl http://localhost:8000/api/v1/analysis/<analysis_id>/findings
curl http://localhost:8000/api/v1/analysis/<analysis_id>/reports/markdown
```

To analyze a real repository instead of the bundled fixture, pass `repo_url`/`branch` instead of
`local_path`. Security scanners that aren't installed on the host are automatically skipped (with
a warning, not a failure) — install `semgrep`, `bandit`, `gitleaks`, `trufflehog`, `pip-audit`,
`osv-scanner`, `trivy`, and/or `checkov` for fuller coverage; the Docker image installs the
pip-installable subset (semgrep, bandit, pip-audit, checkov) by default.

## Running with real LLM providers

By default `MODEL_MOCK_MODE=true` — no API keys needed. To use a real provider, set the relevant
key(s) in `.env` (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY`,
`AZURE_OPENAI_API_KEY`+`AZURE_OPENAI_ENDPOINT`, or point `OLLAMA_BASE_URL` at a local Ollama
daemon), set `MODEL_MOCK_MODE=false`, and pass the matching `model_profile` (`openai`, `gemini`,
`azure`, `local-ollama`, or the default Anthropic-based `default` profile) in your analysis
request. See [docs/model_strategy.md](docs/model_strategy.md).

## Makefile targets

| Command | Description |
|---|---|
| `make install` | Install the package and dev dependencies |
| `make run` | Run the API locally with uvicorn (hot reload) |
| `make test` | Run the test suite |
| `make lint` | Run ruff + mypy |
| `make docker-up` / `make docker-down` | Start/stop the full docker-compose stack |
| `make analyze-sample` | Submit the bundled vulnerable sample repo for analysis |

## What's implemented (MVP)

- FastAPI gateway with all 8 required endpoints (`POST /api/v1/analysis`,
  `GET .../status`, `.../findings`, `.../reports/{json,markdown,sarif}`, `/health`, `/ready`).
- LangGraph coordinator + 6-node linear workflow (repo_ingestion → sast → secrets → dependency →
  remediation → report), with a conditional short-circuit to `report` on fatal ingestion failure.
- 6 working agents (`app/agents/`) extending a common `BaseAgent`, each independently testable.
- `ToolRunner` abstraction running 8 real scanner adapters (Semgrep, Bandit, Gitleaks,
  TruffleHog, pip-audit, OSV-Scanner, Trivy, Checkov) plus a Git ingestion wrapper — every tool
  gracefully degrades to a warning if not installed, verified in this session by running the
  full pipeline with only Bandit installed and confirming real findings flow through end-to-end.
- `LiteLLMModelClient` with role-based routing across 5 roles and 6 provider profiles (including
  a fully offline mock profile), secret redaction before any prompt leaves the process.
- Typed Pydantic v2 contracts for every domain object named in the spec (`Finding`,
  `AnalysisJob`, `ToolExecutionResult`, etc.) in `app/api/schemas.py`.
- SQLAlchemy async persistence (SQLite locally, Postgres in compose) with a repository layer.
- JSON, Markdown, and SARIF-like report generators, all format-tested.
- OpenTelemetry traces (FastAPI + per-agent-node + per-tool + per-LLM-call spans), 10
  spec-named metrics, structured JSON logs — all correlated by `analysis_id`.
- Full local observability stack via docker-compose (otel-collector, Prometheus, Grafana with
  provisioned datasources and an MVP dashboard, Loki, Tempo).
- Secret redaction applied before code reaches LLM prompts, logs, or persisted findings.
- 40 passing tests (unit + integration), including a full HTTP-level integration test that
  creates an analysis, polls status, and fetches all three report formats.

## What's scaffolded, not implemented (final architecture)

Per the spec, these are documented and interface-shaped but not functional in the MVP:

- **MCP integrations** (`app/mcp/`): `MCPToolAdapter` interface + registry + 6 named placeholder
  adapters (GitHub, Azure DevOps, Jira, SonarQube, Vulnerability DB, Vault). All return empty
  tool lists / raise a clear "not configured" error — no live MCP server is required or assumed.
- **4 future agents** (`app/agents/future_*.py`): Code Understanding, IaC/Cloud Security, Threat
  Modeling, Validation/Exploitability — defined as `BaseAgent` subclasses with a no-op `run()`,
  not wired into the graph.
- **Vector store / RAG** (`app/persistence/vector_store.py`): a real in-memory cosine-similarity
  implementation for testing, plus stub classes for pgvector/Qdrant/Azure AI Search.
- **Object storage** (`app/persistence/object_store.py`): a real local-filesystem implementation,
  plus stub classes for S3-compatible and Azure Blob storage.
- **AuthN/AuthZ/rate limiting** (`app/core/security.py`): placeholder classes that raise
  `NotImplementedError`, not wired into any route.
- **Cloud deployment** (`infra/azure/`, `infra/aws/`): placeholder Bicep/Terraform + READMEs
  documenting the intended shape, not deployable as-is.
- **Job queue**: analysis execution uses FastAPI `BackgroundTasks` in the MVP, not a real
  message queue (Redis Queue/RabbitMQ/Service Bus/SQS) — swapping this in is documented in
  [docs/extension_points.md](docs/extension_points.md).
- **Checkpointing**: `app/orchestration/checkpoints.py` returns `None` (no durable checkpointer)
  in the MVP; `build_graph()` already accepts a `checkpointer` param for a future Postgres-backed
  one.

See [docs/extension_points.md](docs/extension_points.md) for concrete, file-level instructions
to implement any of the above.

## Known limitations

- The SARIF report is SARIF-2.1.0-*shaped*, not a certified/validated SARIF document — no rule
  taxonomy validation, fingerprinting, or baselining. See the limitations note at the top of
  `app/reports/sarif_report.py`.
- `osv-scanner` severity is not parsed from its CVSS vector strings; findings fall back to a
  configured default severity (`medium`) — a real CVSS parser is future work.
- LLM-based finding enrichment/remediation is capped (top 5 for analysis enrichment, top 10 for
  remediation, critical/high only) to bound cost — this is a deliberate MVP tradeoff, not a bug.
- No message queue: concurrent analyses share the FastAPI process's background task pool: fine
  for local/dev use, not production job-queue semantics.
- Grafana dashboard PromQL assumes the OTel Collector's Prometheus exporter naming conventions;
  verify metric names against your collector version if they drift.

## Testing

```bash
make test
```

40 tests across `tests/unit/` (config loading, tool adapters, ToolRunner availability handling,
secret redaction, mock model client + routing, LangGraph state transitions, all three report
generators) and `tests/integration/` (a full HTTP-level analysis run against the bundled
vulnerable sample repo, including status polling and all three report endpoints).

## Repository layout

See the top of [docs/architecture.md](docs/architecture.md) for a narrative walkthrough; the
directory structure itself follows the layout specified for this project (`app/api`, `app/core`,
`app/orchestration`, `app/agents`, `app/models`, `app/tools`, `app/mcp`, `app/langchain_utils`,
`app/persistence`, `app/reports`, `app/observability`, `configs/`, `infra/`, `docs/`, `tests/`).
