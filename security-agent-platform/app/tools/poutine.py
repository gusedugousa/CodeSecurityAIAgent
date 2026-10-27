"""poutine CI/CD pipeline security scanner adapter (boostsecurityio/poutine).

Confirmed working against plain (non-git) directories via `analyze_local`, so no
.git requirement gates has_scannable_target. Produces real SARIF 2.1.0.
"""

from __future__ import annotations

import json
from typing import Any

from app.tools._sarif_shared import parse_sarif_v2_results, sarif_result_to_finding
from app.tools.base import ToolAdapter

_SEVERITY_MAPPING = {"error": "critical", "warning": "high", "note": "medium"}


class PoutineAdapter(ToolAdapter):
    name = "poutine"
    category = "cicd"

    def build_command(self, target_path: str, config: dict[str, Any]) -> list[str]:
        args = config.get("args", ["analyze_local", "--format", "sarif"])
        return [self.name, *args, target_path]

    def parse_output(
        self, stdout: str, stderr: str, exit_code: int
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        try:
            data = json.loads(stdout) if stdout.strip() else {}
        except json.JSONDecodeError:
            return [], {"raw_stdout": stdout, "raw_stderr": stderr, "parse_error": "invalid_json"}

        normalized_results = parse_sarif_v2_results(data)
        findings = [
            sarif_result_to_finding(r, self.name, self.category, _SEVERITY_MAPPING)
            for r in normalized_results
        ]
        return findings, {"result_count": len(normalized_results)}
