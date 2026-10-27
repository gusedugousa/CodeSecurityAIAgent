"""pip-audit dependency vulnerability adapter."""

from __future__ import annotations

import json
import os
from typing import Any

import shutil

from app.tools.base import ToolAdapter

_COMMAND = "pip-audit"
_PYTHON_DEPENDENCY_FILES = ("requirements.txt", "pyproject.toml", "Pipfile", "setup.py")


class PipAuditAdapter(ToolAdapter):
    name = "pip_audit"
    category = "dependency"

    def is_available(self) -> bool:
        return shutil.which(_COMMAND) is not None

    def has_scannable_target(self, target_path: str) -> bool:
        # Without a requirement file, `pip-audit` with no -r/-l falls back to auditing
        # the *running* interpreter's environment (i.e. this platform's own dependencies)
        # instead of the scanned project — always wrong for a target with no Python deps.
        return any(
            os.path.isfile(os.path.join(target_path, name)) for name in _PYTHON_DEPENDENCY_FILES
        )

    def build_command(self, target_path: str, config: dict[str, Any]) -> list[str]:
        args = config.get("args", ["--format", "json"])
        requirements_path = os.path.join(target_path, "requirements.txt")
        if os.path.isfile(requirements_path):
            return [_COMMAND, *args, "-r", requirements_path]
        return [_COMMAND, *args, "--path", target_path]

    def parse_output(
        self, stdout: str, stderr: str, exit_code: int
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        default_severity = "high"
        try:
            data = json.loads(stdout) if stdout.strip() else {}
        except json.JSONDecodeError:
            return [], {"raw_stdout": stdout, "raw_stderr": stderr, "parse_error": "invalid_json"}

        dependencies = data.get("dependencies", []) if isinstance(data, dict) else data
        findings: list[dict[str, Any]] = []
        for dependency in dependencies:
            name = dependency.get("name", "unknown")
            version = dependency.get("version", "unknown")
            for vuln in dependency.get("vulns", []) or []:
                fix_versions = vuln.get("fix_versions", [])
                findings.append(
                    {
                        "title": f"{name} {version}: {vuln.get('id', 'unknown-vuln')}",
                        "description": vuln.get("description", ""),
                        "severity": default_severity,
                        "confidence": "high",
                        "category": "dependency",
                        "cwe": None,
                        "owasp": None,
                        "file_path": None,
                        "line_start": None,
                        "line_end": None,
                        "code_snippet": None,
                        "recommendation": (
                            f"Upgrade to one of: {', '.join(fix_versions)}"
                            if fix_versions
                            else None
                        ),
                        "source_tool": self.name,
                        "metadata": {
                            "package": name,
                            "installed_version": version,
                            "vuln_id": vuln.get("id"),
                            "fix_versions": fix_versions,
                        },
                    }
                )
        return findings, {"dependency_count": len(dependencies)}
