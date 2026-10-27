"""Bandit SAST adapter (Python-specific)."""

from __future__ import annotations

import json
from typing import Any

from app.tools.base import ToolAdapter


class BanditAdapter(ToolAdapter):
    name = "bandit"
    category = "sast"

    def build_command(self, target_path: str, config: dict[str, Any]) -> list[str]:
        args = config.get("args", ["-r", "-f", "json"])
        return [self.name, *args, target_path]

    def parse_output(
        self, stdout: str, stderr: str, exit_code: int
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        severity_mapping = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
        try:
            data = json.loads(stdout) if stdout.strip() else {}
        except json.JSONDecodeError:
            return [], {"raw_stdout": stdout, "raw_stderr": stderr, "parse_error": "invalid_json"}

        confidence_mapping = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
        findings: list[dict[str, Any]] = []
        for result in data.get("results", []):
            severity = severity_mapping.get(result.get("issue_severity", "LOW"), "low")
            confidence = confidence_mapping.get(result.get("issue_confidence", "LOW"), "low")
            findings.append(
                {
                    "title": result.get("test_name", "bandit finding"),
                    "description": result.get("issue_text", ""),
                    "severity": severity,
                    "confidence": confidence,
                    "category": "sast",
                    "cwe": _cwe_from_result(result),
                    "owasp": None,
                    "file_path": result.get("filename"),
                    "line_start": result.get("line_number"),
                    "line_end": result.get("line_number"),
                    "code_snippet": result.get("code"),
                    "source_tool": self.name,
                    "metadata": {"test_id": result.get("test_id")},
                }
            )
        return findings, {"errors": data.get("errors", [])}


def _cwe_from_result(result: dict[str, Any]) -> str | None:
    cwe = result.get("issue_cwe")
    if isinstance(cwe, dict) and cwe.get("id") is not None:
        return f"CWE-{cwe['id']}"
    return None
