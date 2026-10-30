# Security policy

This project is a proof of concept and has no authentication or authorization layer. Do not
expose it to untrusted networks, and do not point it at repositories you are not allowed to scan.

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's private vulnerability reporting
("Security" tab -> "Report a vulnerability") on this repository. Include the affected version,
reproduction steps and impact. We aim to acknowledge reports within a week.

## Scope notes

- `tests/fixtures/sample_vulnerable_repo` is intentionally vulnerable; reports about it are not
  vulnerabilities.
- Code snippets are sent to whichever LLM provider you configure. Secret redaction is
  pattern-based and best effort.
