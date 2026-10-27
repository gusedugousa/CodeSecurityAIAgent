"""Gitleaks secret-scanning adapter. Secret values are redacted before leaving this module.

Gitleaks does not reliably write its --report-format json output to /dev/stdout in this
runtime (the file it opens for --report-path is not the process's real stdout fd), so this
adapter writes to a real temp file per run and reads it back in parse_output. A non-zero
exit code (1) simply means "leaks were found" for gitleaks, not a tool failure - the
ToolRunner already parses output regardless of exit code, so this is not special-cased.
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any

from app.core.security import redact_secrets
from app.tools.base import ToolAdapter


class GitleaksAdapter(ToolAdapter):
    name = "gitleaks"
    category = "secrets"

    def __init__(self) -> None:
        self._report_path: str | None = None

    def build_command(self, target_path: str, config: dict[str, Any]) -> list[str]:
        args = config.get(
            "args", ["detect", "--no-git", "--no-banner", "--report-format", "json"]
        )
        fd, self._report_path = tempfile.mkstemp(suffix=".json", prefix="gitleaks-")
        os.close(fd)
        return [self.name, *args, "--report-path", self._report_path, "--source", target_path]

    def parse_output(
        self, stdout: str, stderr: str, exit_code: int
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        default_severity = "critical"
        report_text = stdout
        if self._report_path and os.path.isfile(self._report_path):
            try:
                with open(self._report_path, "r", encoding="utf-8") as fh:
                    report_text = fh.read()
            finally:
                try:
                    os.remove(self._report_path)
                except OSError:
                    pass

        try:
            data = json.loads(report_text) if report_text.strip() else []
        except json.JSONDecodeError:
            return [], {"raw_stdout": stdout, "raw_stderr": stderr, "parse_error": "invalid_json"}

        if not isinstance(data, list):
            return [], {"raw_stdout": stdout, "parse_error": "unexpected_shape"}

        findings: list[dict[str, Any]] = []
        for leak in data:
            secret_value = leak.get("Match") or leak.get("Secret") or ""
            findings.append(
                {
                    "title": f"Secret detected: {leak.get('RuleID', 'unknown-rule')}",
                    "description": redact_secrets(leak.get("Description", "")),
                    "severity": default_severity,
                    "confidence": "high",
                    "category": "secrets",
                    "cwe": "CWE-798",
                    "owasp": None,
                    "file_path": leak.get("File"),
                    "line_start": leak.get("StartLine"),
                    "line_end": leak.get("EndLine"),
                    "code_snippet": redact_secrets(secret_value),
                    "source_tool": self.name,
                }
            )
        return findings, {"leak_count": len(data)}
