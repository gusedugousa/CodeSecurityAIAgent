"""Markdown report generation for a completed (or partial) security analysis."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from app.reports._shared import as_dict, severity_sort_key


def _escape_pipe(text: str) -> str:
    return text.replace("|", "\\|")


def _truncate(text: str, limit: int = 60) -> str:
    text = text.replace("\n", " ").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


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


def _default_executive_summary(findings: list[dict]) -> str:
    if not findings:
        return "No findings detected."
    file_count = len({f.get("file_path") for f in findings if f.get("file_path")})
    highest = min(
        (f.get("severity") for f in findings if f.get("severity")),
        key=lambda s: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(s, 99),
        default="unknown",
    )
    return f"{len(findings)} findings across {file_count} files, highest severity: {highest}."


def _repository_section(repository_metadata: dict | None) -> list[str]:
    lines = ["## Repository Metadata", ""]
    if not repository_metadata:
        lines.append("No repository metadata available.")
        lines.append("")
        return lines
    repo = repository_metadata
    lines.append("| Field | Value |")
    lines.append("|---|---|")
    lines.append(f"| repo_url | {repo.get('repo_url') or 'N/A'} |")
    lines.append(f"| local_path | {repo.get('local_path') or 'N/A'} |")
    lines.append(f"| branch | {repo.get('branch') or 'N/A'} |")
    lines.append(f"| commit_sha | {repo.get('commit_sha') or 'N/A'} |")
    lines.append(f"| file_count | {repo.get('file_count', 'N/A')} |")
    languages = repo.get("primary_languages") or []
    lines.append(f"| primary_languages | {', '.join(languages) if languages else 'N/A'} |")
    lines.append("")
    return lines


def _severity_section(severity_summary: dict | None) -> list[str]:
    lines = ["## Severity Summary", ""]
    summary = severity_summary or {}
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for key in ("critical", "high", "medium", "low", "info", "total"):
        lines.append(f"| {key} | {summary.get(key, 0)} |")
    lines.append("")
    return lines


def _findings_table_section(findings: list[dict]) -> list[str]:
    lines = ["## Findings Table", ""]
    if not findings:
        lines.append("No findings detected.")
        lines.append("")
        return lines
    lines.append("| ID | Title | Severity | Category | File | Line |")
    lines.append("|---|---|---|---|---|---|")
    for f in findings:
        title = _escape_pipe(_truncate(f.get("title") or ""))
        file_path = f.get("file_path") or "N/A"
        line_start = f.get("line_start")
        line_end = f.get("line_end")
        if line_start is not None and line_end is not None:
            line_display = f"{line_start}-{line_end}" if line_end != line_start else str(line_start)
        elif line_start is not None:
            line_display = str(line_start)
        else:
            line_display = "N/A"
        lines.append(
            f"| {f.get('id', '')} | {title} | {f.get('severity', '')} | "
            f"{f.get('category', '')} | {file_path} | {line_display} |"
        )
    lines.append("")
    return lines


def _detailed_findings_section(findings: list[dict]) -> list[str]:
    lines = ["## Detailed Findings", ""]
    if not findings:
        lines.append("No findings detected.")
        lines.append("")
        return lines
    for f in findings:
        severity = (f.get("severity") or "unknown").upper()
        title = f.get("title") or "Untitled finding"
        finding_id = f.get("id", "")
        lines.append(f"### [{severity}] {title} ({finding_id})")
        lines.append("")
        if f.get("description"):
            lines.append(f.get("description"))
            lines.append("")
        file_path = f.get("file_path")
        if file_path:
            line_start = f.get("line_start")
            line_end = f.get("line_end")
            if line_start is not None and line_end is not None:
                location = f"{file_path}:{line_start}-{line_end}"
            elif line_start is not None:
                location = f"{file_path}:{line_start}"
            else:
                location = file_path
            lines.append(f"**Location:** {location}")
            lines.append("")
        if f.get("code_snippet"):
            lines.append("```")
            lines.append(f.get("code_snippet"))
            lines.append("```")
            lines.append("")
        if f.get("cwe"):
            lines.append(f"**CWE:** {f.get('cwe')}")
            lines.append("")
        if f.get("owasp"):
            lines.append(f"**OWASP:** {f.get('owasp')}")
            lines.append("")
        evidence_list = f.get("evidence") or []
        if evidence_list:
            lines.append("**Evidence:**")
            lines.append("")
            for ev_raw in evidence_list:
                ev = as_dict(ev_raw)
                desc = ev.get("description") or ""
                lines.append(f"- {desc}")
                if ev.get("snippet"):
                    lines.append("  ```")
                    lines.append(f"  {ev.get('snippet')}")
                    lines.append("  ```")
            lines.append("")
        if f.get("business_impact"):
            lines.append("**Business Impact:**")
            lines.append("")
            lines.append(f.get("business_impact"))
            lines.append("")
        if f.get("attack_scenario"):
            lines.append("**Attack Scenario:**")
            lines.append("")
            lines.append(f.get("attack_scenario"))
            lines.append("")
        if f.get("recommendation"):
            lines.append("**Recommendation:**")
            lines.append("")
            lines.append(f.get("recommendation"))
            lines.append("")
        remediation = f.get("remediation")
        if remediation:
            remediation = as_dict(remediation)
            lines.append("**Remediation Suggestion:**")
            lines.append("")
            if remediation.get("summary"):
                lines.append(remediation.get("summary"))
                lines.append("")
            if remediation.get("explanation"):
                lines.append(remediation.get("explanation"))
                lines.append("")
            if remediation.get("patch_diff"):
                lines.append("```diff")
                lines.append(remediation.get("patch_diff"))
                lines.append("```")
                lines.append("")
        lines.append("---")
        lines.append("")
    return lines


def _tool_coverage_section(coverage: list[dict]) -> list[str]:
    lines = ["## Tool Coverage", ""]
    if not coverage:
        lines.append("No tool execution results available.")
        lines.append("")
        return lines
    lines.append("| Tool | Category | Available | Findings Count |")
    lines.append("|---|---|---|---|")
    for tool in coverage:
        lines.append(
            f"| {tool.get('tool_name', '')} | {tool.get('category', '')} | "
            f"{tool.get('available', False)} | {tool.get('findings_count', 0)} |"
        )
    lines.append("")
    return lines


def _tools_unavailable_section(coverage: list[dict]) -> list[str]:
    lines = ["## Tools Unavailable", ""]
    unavailable = [t.get("tool_name") for t in coverage if not t.get("available")]
    if not unavailable:
        lines.append("All configured tools were available.")
    else:
        for name in unavailable:
            lines.append(f"- {name}")
    lines.append("")
    return lines


def generate_markdown_report(
    analysis_id: str,
    findings: list[dict],
    repository_metadata: dict | None,
    severity_summary: dict | None,
    tool_results: list[dict],
    executive_summary: str | None,
    warnings: list[str],
    generated_at: datetime | None = None,
) -> str:
    findings = [as_dict(f) for f in (findings or [])]
    repository_metadata = as_dict(repository_metadata) if repository_metadata else None
    severity_summary = as_dict(severity_summary) if severity_summary else None
    tool_results = [as_dict(t) for t in (tool_results or [])]
    warnings = list(warnings or [])
    timestamp = generated_at or datetime.now(timezone.utc)

    sorted_findings = sorted(findings, key=severity_sort_key)
    coverage = _tool_coverage(tool_results)

    lines: list[str] = []
    lines.append(f"# Security Analysis Report — {analysis_id}")
    lines.append("")
    lines.append(f"_Generated at {timestamp.isoformat()}_")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(executive_summary or _default_executive_summary(sorted_findings))
    lines.append("")

    if warnings:
        lines.append("**Warnings:**")
        lines.append("")
        for w in warnings:
            lines.append(f"- {w}")
        lines.append("")

    lines.extend(_repository_section(repository_metadata))
    lines.extend(_severity_section(severity_summary))
    lines.extend(_findings_table_section(sorted_findings))
    lines.extend(_detailed_findings_section(sorted_findings))
    lines.extend(_tool_coverage_section(coverage))
    lines.extend(_tools_unavailable_section(coverage))

    return "\n".join(lines).rstrip() + "\n"


def write_markdown_report(content: str, output_path: str) -> int:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return len(content.encode("utf-8"))
