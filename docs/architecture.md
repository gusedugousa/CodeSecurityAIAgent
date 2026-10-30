# Architecture

## MVP architecture

The MVP is a single FastAPI service that accepts an analysis request, runs a LangGraph state
machine over a target repository, and persists findings/reports. It is designed to run
identically on a laptop (`docker-compose up`) or as a single container in any orchestrator.

```
Client (API/CLI)
      |
      v
FastAPI Gateway  --(placeholders: authn/authz/rate limit)-->  POST /api/v1/analysis
      |
      v
Coordinator Agent  --creates AnalysisState, analysis_id-->
      |
      v
LangGraph state machine (app/orchestration/graph.py)
  START -> repo_ingestion -> sast -> secrets -> dependency -> remediation -> report -> END
      |                          |         |          |            |            |
      v                          v         v          v            v            v
  GitRepositoryIngestor   Semgrep/Bandit  Gitleaks/  pip-audit/   LiteLLM      severity
  (clone or local path)                  TruffleHog  OSV/Trivy/   remediation  summary +
                                                      Checkov     suggestions  executive
                                                                                summary
      |
      v
Persistence (SQLAlchemy async: SQLite locally, Postgres in compose)
      |
      v
Report generation (app/reports/*.py): JSON, Markdown, SARIF-like, written to disk
      |
      v
GET /api/v1/analysis/{id}/{status,findings,reports/*}
```

Every tool run is wrapped by `ToolRunner`, which never raises: an unavailable or failing tool
becomes a `warnings` entry, not a fatal error, so the platform stays useful with whatever subset
of scanners happens to be installed. Every LLM call goes through `LiteLLMModelClient`, which
supports a fully offline, deterministic **mock mode** so the entire pipeline — including
LangGraph execution — is testable and runnable with zero API keys.

## Why LangGraph is the orchestrator

The platform's core problem is a **stateful, multi-step workflow** with conditional branching
(e.g. skip scanning entirely on a fatal repo-ingestion failure), not a linear prompt chain.
LangGraph models this directly: an explicit `StateGraph` with typed state
(`app/orchestration/state.py::AnalysisState`), named nodes per agent, and explicit edges —
including a conditional edge that routes straight to the report node if ingestion fails fatally.
This graph is inspectable, testable node-by-node, and — because LangGraph's `.compile()` accepts
a `checkpointer` — ready for durable, resumable execution once a real checkpoint backend is
wired in (see `app/orchestration/checkpoints.py`), without changing the graph's shape.

Critically, the graph's nodes are agents, and agents are Python classes with a plain
`async def run(self, state) -> state` contract (`app/agents/base.py::BaseAgent`). Every node is
independently unit-testable outside of LangGraph.

## The limited role of LangChain

LangChain is used **only** as a utility library inside individual agents
(`app/langchain_utils/`): `PromptTemplate` for prompt construction, `PydanticOutputParser`/JSON
extraction for structured LLM output, `RecursiveCharacterTextSplitter` for chunking large files,
and a minimal retriever abstraction for future RAG. None of these compose into a LangChain
`Chain`, `AgentExecutor`, or LCEL pipeline — there is no LangChain-managed control flow anywhere
in the system. Multi-step orchestration is exclusively LangGraph's job. This split keeps the
orchestration layer swappable (a different graph engine could replace LangGraph without touching
agent internals) and keeps LangChain's surface area small and auditable.

## LiteLLM as the model gateway

`app/models/litellm_client.py::LiteLLMModelClient` wraps `litellm.acompletion`, giving every
agent the same interface regardless of the underlying provider (OpenAI, Anthropic, Gemini, Azure
OpenAI, Ollama). Role-based routing (`app/models/routing.py::ModelRouter`) resolves an abstract
role like `analysis_model` to a concrete `provider/model` string via `configs/models.yaml`
profiles, so swapping providers, running a hybrid setup, or adding a fallback model is a config
change. See `docs/model_strategy.md` for the full routing/mock-mode/cost design.

## MCP tool strategy

The platform defines `MCPToolAdapter` (`app/mcp/adapter.py`) as the extension point for
Model Context Protocol servers (GitHub, Azure DevOps, Jira, SonarQube, a vulnerability DB,
Vault). The MVP does not require any live MCP server — every registered adapter is a
`NullMCPToolAdapter`-derived placeholder that reports itself as unconfigured rather than
crashing. See `docs/mcp_strategy.md` for the full design and how to wire in a real client later.

## Observability architecture

OpenTelemetry is the vendor-neutral standard used throughout: FastAPI request spans, one span
per LangGraph node (`agent_node_span`), one span per tool execution (`tool_execution_span`), one
span per LLM call (`model_call_span`), each carrying `analysis_id` plus context-appropriate
attributes (repo_url, tool_name, model_name, token counts, cost_estimate, duration_ms,
findings_count). Metrics (`app/observability/metrics.py`) and structured JSON logs
(`app/core/logging.py` + `app/observability/events.py`) are correlated by the same `analysis_id`.
See `docs/observability.md` for the full trace/metric/log design and local Grafana setup.

## Final architecture (documented, partially scaffolded)

The final architecture (see the project's top-level spec, section 3) extends the MVP along
several axes without requiring a rewrite of what exists:

- **More inputs**: GitHub/GitLab/Bitbucket/Azure DevOps webhooks, CI/CD pipeline triggers, a web
  UI — all funnel into the same `POST /api/v1/analysis` contract the MVP already exposes.
- **More agents**: `app/agents/future_code_understanding_agent.py`,
  `future_iac_cloud_security_agent.py`, `future_threat_modeling_agent.py`, and
  `future_validation_agent.py` are scaffolded `BaseAgent` subclasses, not wired into the MVP
  graph. Adding one to the final graph is a `graph.add_node(...)` + `graph.add_edge(...)` change
  in `app/orchestration/graph.py` — see `docs/extension_points.md`.
- **Job queue**: Redis Queue / RabbitMQ / Azure Service Bus / SQS replacing the MVP's in-process
  FastAPI `BackgroundTasks`, behind the same `coordinate_analysis()` entry point.
- **Real MCP integrations**: concrete subclasses of `MCPToolAdapter` replacing the placeholders.
- **RAG knowledge layer**: `app/persistence/vector_store.py`'s `VectorStore` ABC, currently
  backed by an in-memory placeholder, swapped for pgvector/Qdrant/Azure AI Search.
- **Cloud deployment**: `infra/azure/` and `infra/aws/` hold placeholder IaC (Bicep/Terraform)
  documenting — not yet automating — deployment to Azure Container Apps or AWS ECS.

No part of the MVP is built in a way that hard-codes a specific cloud provider; every external
integration point named above is an interface the MVP already defines.
