"""Trufflehog secret-scanning adapter (JSONL output). Raw secret values are redacted."""

from __future__ import annotations

import json
from typing import Any

from app.core.security import redact_secrets
from app.tools.base import ToolAdapter


class TrufflehogAdapter(ToolAdapter):
    name = "trufflehog"
    category = "secrets"

    def build_command(self, target_path: str, config: dict[str, Any]) -> list[str]:
        args = config.get("args", ["filesystem", "--json"])
        return [self.name, *args, target_path]

    def parse_output(
        self, stdout: str, stderr: str, exit_code: int
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        default_severity = "high"
        findings: list[dict[str, Any]] = []
        malformed_lines = 0

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                malformed_lines += 1
                continue

            source_metadata = record.get("SourceMetadata", {})
            data = source_metadata.get("Data", {}) if isinstance(source_metadata, dict) else {}
            filesystem_data = data.get("Filesystem", {}) if isinstance(data, dict) else {}

            findings.append(
                {
                    "title": f"Secret detected: {record.get('DetectorName', 'unknown-detector')}",
                    "description": "Potential secret found by trufflehog.",
                    "severity": default_severity,
                    "confidence": "high" if record.get("Verified") else "medium",
                    "category": "secrets",
                    "cwe": "CWE-798",
                    "owasp": None,
                    "file_path": filesystem_data.get("file"),
                    "line_start": filesystem_data.get("line"),
                    "line_end": filesystem_data.get("line"),
                    "code_snippet": redact_secrets(str(record.get("Raw", ""))),
                    "source_tool": self.name,
                }
            )

        if not findings and not stdout.strip():
            return [], {"raw_stdout": stdout, "raw_stderr": stderr}

        return findings, {"malformed_lines": malformed_lines}
