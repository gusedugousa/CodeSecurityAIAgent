# Model Strategy

## Role-based routing, not a single model

Every LLM call in the platform is made on behalf of a **role**, not a hardcoded model name:

- `coordinator_model` — reserved for future coordinator-level reasoning (routing decisions,
  plan adjustment). Not heavily used by the linear MVP graph but present for the target
  architecture's more dynamic coordinator.
- `analysis_model` — SAST/dependency finding triage and context summarization.
- `remediation_model` — patch/explanation generation for high-severity findings.
- `reporting_model` — executive summary generation.
- `cheap_classifier_model` — fast, cheap true/false-positive style classification (e.g. secrets
  triage), intentionally routed to a smaller/cheaper model.

`configs/models.yaml` defines named **profiles** (`default`, `openai`, `gemini`, `azure`,
`local-ollama`, `mock`), each mapping every role to a concrete `provider/model` string consumed
by LiteLLM (e.g. `anthropic/claude-sonnet-4`, `openai/gpt-4.1`, `ollama/qwen2.5-coder`). An
`AnalysisRequest.model_profile` field selects which profile a given analysis run uses.
`app/models/routing.py`'s `ModelRouter.resolve(role, model_profile)` performs the lookup, falling
back to the `default_profile` if the requested profile is unknown.

This means switching providers — or running a hybrid setup where remediation uses a stronger
model than classification — is a config change, not a code change.

## Mock mode: zero API keys required

`configs/models.yaml`'s `mock_mode: true` (also overridable via the `MODEL_MOCK_MODE` env var)
forces every model call through `LiteLLMModelClient`'s deterministic mock path instead of a real
provider. Mock responses are small, role-appropriate canned JSON strings — no network call, near
zero latency, `$0` cost. This is the default in local development specifically so the platform is
fully runnable and testable — including the full LangGraph agent flow — without any provider
credentials. Any model name prefixed `mock/` (as used by the `mock` profile) also forces mock
behavior regardless of the global flag, which is what the test suite uses for determinism.

## Ollama / local models

The `local-ollama` profile routes every role to `ollama/qwen2.5-coder`. LiteLLM talks to a local
Ollama daemon (`OLLAMA_BASE_URL`, default `http://localhost:11434`) — no API key, no outbound
network call beyond localhost. This is the recommended profile for fully offline, fully real
(non-mocked) local testing when API budget or network access is a constraint.

## Cost estimation

`configs/models.yaml`'s `cost_table_per_1k_tokens` gives approximate USD input/output rates per
model, used only to populate `ModelCallMetadata.cost_estimate` for observability (the
`llm_cost_estimate_total` metric) — it is not a source of truth for actual billing and should not
be relied on for invoicing.

## Future: fallback models, retry policy, cost routing

The target architecture calls for fallback models (if the primary model errors or
times out, retry against a secondary), token budgeting per analysis, and cost-aware routing
(cheaper model first, escalate only if needed). The MVP's `LiteLLMModelClient` already retries
transient failures against the *same* model (`tenacity`-based, configurable via
`request_defaults.retry_count`/`retry_backoff_seconds`), but does not yet fall back to a
*different* model or dynamically choose models by cost/budget — `ModelRouter` is the natural
extension point: a future version would resolve to an ordered list of candidate models per role,
attempted in sequence, with budget/spend tracked per `analysis_id`.
