# Contributing

Thanks for your interest. This is a proof of concept, so the most useful contributions are
new scanner adapters, better prompts and parsers, real-LLM test cases, and documentation fixes.

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
make install
make test
make lint
```

Python 3.11+. No API keys are needed: tests run in mock model mode.

## Before opening a pull request

- Keep changes focused; one concern per PR.
- Add or update tests. `make test` and `ruff check app tests scripts` must pass.
- Update the docs if behavior changes.
- Never commit secrets, real credentials or code from private repositories.

## Where things go

[docs/extension_points.md](docs/extension_points.md) explains how to add a scanner adapter, an
agent, a model profile, a report format or an MCP adapter. Each follows an existing pattern.

## Reporting bugs and ideas

Use the issue templates. For security vulnerabilities in this project, follow
[SECURITY.md](SECURITY.md) instead of opening a public issue.

## Conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
