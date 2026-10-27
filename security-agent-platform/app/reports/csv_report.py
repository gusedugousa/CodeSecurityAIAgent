"""CSV report generation: one row per finding, full detail, for spreadsheet-based review."""

from __future__ import annotations

import csv
import io
from pathlib import Path

from app.reports._shared import as_dict, severity_sort_key

FIELDNAMES = [
    "repo_url",
    "branch",
    "commit_sha",
    "id",
    "title",
    "severity",
    "confidence",
    "category",
    "cwe",
    "owasp",
    "file_path",
    "line_start",
    "line_end",
    "source_tool",
    "source_agent",
    "validation_status",
    "false_positive_reason",
    "description",
    "code_snippet",
    "attack_scenario",
    "business_impact",
    "recommendation",
    "remediation_summary",
    "remediation_explanation",
    "remediation_patch_diff",
    "remediation_generated_by_model",
    "evidence_summary",
    "created_at",
]


def _evidence_summary(evidence: list[dict]) -> str:
    parts = []
    for item in evidence or []:
        item = as_dict(item)
        source = item.get("source") or "unknown"
        description = item.get("description") or ""
        parts.append(f"[{source}] {description}".strip())
    return " | ".join(parts)


def _finding_to_row(finding: dict, repo_fields: dict) -> dict:
    remediation = as_dict(finding.get("remediation")) if finding.get("remediation") else {}
    return {
        **repo_fields,
        "id": finding.get("id"),
        "title": finding.get("title"),
        "severity": finding.get("severity"),
        "confidence": finding.get("confidence"),
        "category": finding.get("category"),
        "cwe": finding.get("cwe"),
        "owasp": finding.get("owasp"),
        "file_path": finding.get("file_path"),
        "line_start": finding.get("line_start"),
        "line_end": finding.get("line_end"),
        "source_tool": finding.get("source_tool"),
        "source_agent": finding.get("source_agent"),
        "validation_status": finding.get("validation_status"),
        "false_positive_reason": finding.get("false_positive_reason"),
        "description": finding.get("description"),
        "code_snippet": finding.get("code_snippet"),
        "attack_scenario": finding.get("attack_scenario"),
        "business_impact": finding.get("business_impact"),
        "recommendation": finding.get("recommendation"),
        "remediation_summary": remediation.get("summary"),
        "remediation_explanation": remediation.get("explanation"),
        "remediation_patch_diff": remediation.get("patch_diff"),
        "remediation_generated_by_model": remediation.get("generated_by_model"),
        "evidence_summary": _evidence_summary(finding.get("evidence") or []),
        "created_at": finding.get("created_at"),
    }


def generate_csv_report(
    analysis_id: str, findings: list[dict], repository_metadata: dict | None = None
) -> str:
    findings = [as_dict(f) for f in (findings or [])]
    findings.sort(key=severity_sort_key)
    repository_metadata = as_dict(repository_metadata) if repository_metadata else {}
    repo_fields = {
        "repo_url": repository_metadata.get("repo_url"),
        "branch": repository_metadata.get("branch"),
        "commit_sha": repository_metadata.get("commit_sha"),
    }

    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=FIELDNAMES, extrasaction="ignore")
    writer.writeheader()
    for finding in findings:
        writer.writerow(_finding_to_row(finding, repo_fields))
    return buffer.getvalue()


def write_csv_report(content: str, output_path: str) -> int:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="")
    return len(content.encode("utf-8"))
