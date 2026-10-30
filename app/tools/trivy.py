"""Trivy filesystem dependency vulnerability adapter."""

from __future__ import annotations

import json
from typing import Any

from app.tools.base import ToolAdapter

_SEVERITY_MAPPING = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info",
}


class TrivyAdapter(ToolAdapter):
    name = "trivy"
    category = "dependency"

    def build_command(self, target_path: str, config: dict[str, Any]) -> list[str]:
        args = config.get("args", ["fs", "--format", "json", "--quiet"])
        return [self.name, *args, target_path]

    def parse_output(
        self, stdout: str, stderr: str, exit_code: int
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        try:
            data = json.loads(stdout) if stdout.strip() else {}
        except json.JSONDecodeError:
            return [], {"raw_stdout": stdout, "raw_stderr": stderr, "parse_error": "invalid_json"}

        findings: list[dict[str, Any]] = []
        for result in data.get("Results", []) or []:
            target = result.get("Target")
            for vuln in result.get("Vulnerabilities", []) or []:
                severity = _SEVERITY_MAPPING.get(vuln.get("Severity", "UNKNOWN"), "info")
                findings.append(
                    {
                        "title": f"{vuln.get('PkgName', 'unknown')}: {vuln.get('VulnerabilityID', 'unknown-vuln')}",
                        "description": vuln.get("Description", ""),
                        "severity": severity,
                        "confidence": "high",
                        "category": "dependency",
                        "cwe": _first_cwe(vuln),
                        "owasp": None,
                        "file_path": target,
                        "line_start": None,
                        "line_end": None,
                        "code_snippet": None,
                        "recommendation": (
                            f"Upgrade to {vuln['FixedVersion']}" if vuln.get("FixedVersion") else None
                        ),
                        "source_tool": self.name,
                        "metadata": {
                            "package": vuln.get("PkgName"),
                            "installed_version": vuln.get("InstalledVersion"),
                            "fixed_version": vuln.get("FixedVersion"),
                        },
                    }
                )
        return findings, {}


def _first_cwe(vuln: dict[str, Any]) -> str | None:
    cwe_ids = vuln.get("CweIDs")
    if isinstance(cwe_ids, list) and cwe_ids:
        return str(cwe_ids[0])
    return None
