"""Checkov IaC misconfiguration adapter."""

from __future__ import annotations

import json
from typing import Any

from app.tools.base import ToolAdapter

_SEVERITY_MAPPING = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}
_DEFAULT_SEVERITY = "medium"


class CheckovAdapter(ToolAdapter):
    name = "checkov"
    category = "iac"

    def build_command(self, target_path: str, config: dict[str, Any]) -> list[str]:
        args = config.get("args", ["-d", "--output", "json", "--compact"])
        command = [self.name]
        if "-d" in args:
            idx = args.index("-d")
            command.extend(args[: idx + 1])
            command.append(target_path)
            command.extend(args[idx + 1 :])
        else:
            command.extend(args)
            command.extend(["-d", target_path])
        return command

    def parse_output(
        self, stdout: str, stderr: str, exit_code: int
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        try:
            data = json.loads(stdout) if stdout.strip() else {}
        except json.JSONDecodeError:
            return [], {"raw_stdout": stdout, "raw_stderr": stderr, "parse_error": "invalid_json"}

        results_blocks = data if isinstance(data, list) else [data]

        findings: list[dict[str, Any]] = []
        for block in results_blocks:
            results = block.get("results", {}) if isinstance(block, dict) else {}
            for check in results.get("failed_checks", []) or []:
                severity_raw = check.get("severity")
                severity = _SEVERITY_MAPPING.get(severity_raw, _DEFAULT_SEVERITY)
                line_range = check.get("file_line_range") or [None, None]
                findings.append(
                    {
                        "title": check.get("check_name", check.get("check_id", "checkov finding")),
                        "description": check.get("check_name", ""),
                        "severity": severity,
                        "confidence": "medium",
                        "category": "iac",
                        "cwe": None,
                        "owasp": None,
                        "file_path": check.get("file_path"),
                        "line_start": line_range[0] if len(line_range) > 0 else None,
                        "line_end": line_range[1] if len(line_range) > 1 else None,
                        "code_snippet": None,
                        "source_tool": self.name,
                        "metadata": {
                            "check_id": check.get("check_id"),
                            "resource": check.get("resource"),
                        },
                    }
                )
        return findings, {}
