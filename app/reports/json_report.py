"""JSON report generation for a completed (or partial) security analysis."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from app.reports._shared import as_dict


def _tool_coverage(tool_results: list[dict]) -> list[dict]:
    coverage: list[dict] = []
    for raw in tool_results or []:
        tool = as_dict(raw)
        coverage.append(
            {
                "tool_name": tool.get("tool_name"),
                "category": tool.get("category"),
                "available": bool(tool.get("available", False)),
                "findings_count": tool.get("findings_count", 0),
            }
        )
    return coverage


def generate_json_report(
    analysis_id: str,
    findings: list[dict],
    repository_metadata: dict | None,
    severity_summary: dict | None,
    tool_results: list[dict],
    warnings: list[str],
    generated_at: datetime | None = None,
) -> dict:
    findings = [as_dict(f) for f in (findings or [])]
    repository_metadata = as_dict(repository_metadata) if repository_metadata else None
    severity_summary = as_dict(severity_summary) if severity_summary else None
    tool_results = [as_dict(t) for t in (tool_results or [])]
    warnings = list(warnings or [])

    coverage = _tool_coverage(tool_results)
    tools_unavailable = [t["tool_name"] for t in coverage if not t["available"]]

    timestamp = generated_at or datetime.now(UTC)

    return {
        "analysis_id": analysis_id,
        "generated_at": timestamp.isoformat(),
        "repository": repository_metadata,
        "severity_summary": severity_summary,
        "findings": findings,
        "tool_coverage": coverage,
        "tools_unavailable": tools_unavailable,
        "warnings": warnings,
    }


def write_json_report(report: dict, output_path: str) -> int:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(report, indent=2, default=str)
    path.write_text(content, encoding="utf-8")
    return len(content.encode("utf-8"))
