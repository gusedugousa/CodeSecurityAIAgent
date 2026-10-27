"""Semgrep SAST adapter, plus a second adapter instance running a custom ruleset
scoped to Databricks Asset Bundle config (databricks.yml) - no dedicated, mature tool
exists for that format (confirmed: nothing on GitHub/PyPI with real adoption), so a
generic-pattern Semgrep ruleset is the pragmatic stand-in. Both share the same JSON
parsing body via _parse_semgrep_json; SemgrepDatabricksAdapter forces category="iac"
(matching checkov's category for infra config) and prefixes titles for traceability.
"""

from __future__ import annotations

import json
import os
import shutil
from typing import Any

from app.tools.base import ToolAdapter

_COMMAND = "semgrep"
_DATABRICKS_RULESET_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "configs",
    "semgrep-rules",
    "databricks.yaml",
)


def _parse_semgrep_json(
    stdout: str,
    stderr: str,
    source_tool: str,
    category_override: str | None = None,
    title_prefix: str = "",
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    severity_mapping = {"ERROR": "critical", "WARNING": "medium", "INFO": "low"}
    try:
        data = json.loads(stdout) if stdout.strip() else {}
    except json.JSONDecodeError:
        return [], {"raw_stdout": stdout, "raw_stderr": stderr, "parse_error": "invalid_json"}

    findings: list[dict[str, Any]] = []
    for result in data.get("results", []):
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})
        start = result.get("start", {})
        end = result.get("end", {})
        severity = severity_mapping.get(extra.get("severity", "INFO"), "info")
        findings.append(
            {
                "title": f"{title_prefix}{result.get('check_id', 'semgrep finding')}",
                "description": extra.get("message", ""),
                "severity": severity,
                "confidence": "medium",
                "category": category_override or "sast",
                "cwe": _first_cwe(metadata.get("cwe")),
                "owasp": _first(metadata.get("owasp")),
                "file_path": result.get("path"),
                "line_start": start.get("line"),
                "line_end": end.get("line"),
                "code_snippet": extra.get("lines"),
                "source_tool": source_tool,
            }
        )
    return findings, {"errors": data.get("errors", [])}


class SemgrepAdapter(ToolAdapter):
    name = "semgrep"
    category = "sast"

    def build_command(self, target_path: str, config: dict[str, Any]) -> list[str]:
        args = config.get("args", ["--json", "--quiet", "--config", "auto"])
        return [self.name, *args, target_path]

    def parse_output(
        self, stdout: str, stderr: str, exit_code: int
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        return _parse_semgrep_json(stdout, stderr, self.name)


class SemgrepDatabricksAdapter(ToolAdapter):
    name = "semgrep_databricks"
    category = "iac"

    def is_available(self) -> bool:
        return shutil.which(_COMMAND) is not None

    def has_scannable_target(self, target_path: str) -> bool:
        for _root, _dirs, files in os.walk(target_path):
            if "databricks.yml" in files or "databricks.yaml" in files:
                return True
        return False

    def build_command(self, target_path: str, config: dict[str, Any]) -> list[str]:
        args = config.get(
            "args", ["--json", "--quiet", "--config", _DATABRICKS_RULESET_PATH]
        )
        return [_COMMAND, *args, target_path]

    def parse_output(
        self, stdout: str, stderr: str, exit_code: int
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        return _parse_semgrep_json(
            stdout,
            stderr,
            "semgrep",
            category_override="iac",
            title_prefix="[databricks] ",
        )


def _first(value: Any) -> str | None:
    if isinstance(value, list) and value:
        return str(value[0])
    if isinstance(value, str):
        return value
    return None


def _first_cwe(value: Any) -> str | None:
    return _first(value)
