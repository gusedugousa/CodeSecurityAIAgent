# Changelog

## 0.1.1

- English architecture diagram showing this repository and the broader solution it was extracted from.
- README section documenting the origin and scope of this partial demonstration.
- Unified service naming (telemetry, API title, Grafana) under governed-ai-code-security.
- Added CITATION.cff and a GitHub social preview image.

## 0.1.0 - proof of concept

- LangGraph workflow: repo ingestion, SAST, secrets, dependency/IaC, CI/CD, remediation, report.
- Scanner adapters: Semgrep, Bandit, Meziantou, Gitleaks, TruffleHog, pip-audit, OSV-Scanner,
  Trivy, Checkov, Poutine.
- LiteLLM model client with role-based routing, mock mode and secret redaction.
- JSON, Markdown, CSV and SARIF-shaped reports; OpenTelemetry observability stack.
- CI client (`scripts/ci_scan.py`) and GitHub Actions example.
- Fix: secrets triage prompt now requests the `is_placeholder` key the agent reads.
