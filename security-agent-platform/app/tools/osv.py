"""OSV-Scanner dependency vulnerability adapter."""

from __future__ import annotations

import json
import shutil
from typing import Any

from app.tools.base import ToolAdapter

_COMMAND = "osv-scanner"


class OsvScannerAdapter(ToolAdapter):
    name = "osv_scanner"
    category = "dependency"

    def is_available(self) -> bool:
        return shutil.which(_COMMAND) is not None

    def build_command(self, target_path: str, config: dict[str, Any]) -> list[str]:
        args = config.get("args", ["--format", "json"])
        return [_COMMAND, *args, target_path]

    def parse_output(
        self, stdout: str, stderr: str, exit_code: int
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        default_severity = "medium"
        try:
            data = json.loads(stdout) if stdout.strip() else {}
        except json.JSONDecodeError:
            return [], {"raw_stdout": stdout, "raw_stderr": stderr, "parse_error": "invalid_json"}

        findings: list[dict[str, Any]] = []
        for result in data.get("results", []):
            source = result.get("source", {})
            for package_entry in result.get("packages", []):
                package = package_entry.get("package", {})
                for vuln in package_entry.get("vulnerabilities", []) or []:
                    severity = default_severity
                    findings.append(
                        {
                            "title": f"{package.get('name', 'unknown')}: {vuln.get('id', 'unknown-vuln')}",
                            "description": vuln.get("summary", ""),
                            "severity": severity,
                            "confidence": "high",
                            "category": "dependency",
                            "cwe": None,
                            "owasp": None,
                            "file_path": source.get("path"),
                            "line_start": None,
                            "line_end": None,
                            "code_snippet": None,
                            "source_tool": self.name,
                            "metadata": {
                                "package": package.get("name"),
                                "ecosystem": package.get("ecosystem"),
                                "version": package.get("version"),
                                "vuln_id": vuln.get("id"),
                            },
                        }
                    )
        return findings, {}
