"""Deduplicated CSV report: collapses findings from different tools that flag the
same underlying issue into a single row.

Confirmed against real captured data (not just theory) that this is solvable with
deterministic grouping, no LLM/semantic judgment needed:
- SAST/IaC findings: different tools (semgrep, bandit, meziantou) commonly flag the
  exact same file+line as separate findings with unrelated titles/CWEs - grouping by
  (file_path, line block) catches this without understanding what the finding means.
- Dependency findings: pip-audit/osv-scanner/trivy use different vulnerability ID
  formats for the same CVE (GHSA vs CVE prefixes) and don't share a common `cwe`
  field (pip-audit/osv never set it), but all three DO share the package name in
  their title - grouping by normalized package name is a reliable common anchor.

This is a SEPARATE, additional report from csv_report.py (which stays 1-row-per-raw-finding
for full detail) - not a replacement.
"""

from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Any

from app.reports._shared import SEVERITY_ORDER, as_dict

_LINE_BLOCK_SIZE = 3  # tolerate small line-number drift between tools' own line-counting

FIELDNAMES = [
    "repo_url",
    "branch",
    "commit_sha",
    "severity",
    "category",
    "file_path",
    "line_range",
    "title_summary",
    "source_tools",
    "finding_count",
    "cwe",
    "owasp",
    "description",
    "recommendation",
]


def _group_key(finding: dict) -> tuple:
    category = finding.get("category")
    file_path = finding.get("file_path")

    if category in ("sast", "iac") and file_path:
        line_start = finding.get("line_start")
        block = line_start // _LINE_BLOCK_SIZE if isinstance(line_start, int) else None
        return ("location", category, file_path, block)

    if category == "dependency":
        package = _extract_package_name(finding.get("title") or "")
        if package:
            return ("package", package)

    # No reliable grouping anchor - each such finding is its own group, 1:1 with
    # the existing detailed CSV (no false merging of unrelated findings).
    return ("ungrouped", finding.get("id"))


def _extract_package_name(title: str) -> str | None:
    # All three dependency tools (pip-audit, osv-scanner, trivy) format titles as
    # "<package>[ <version>]: <vuln-id>" - the package name is always the first
    # colon-delimited segment, with an optional trailing version token to strip.
    if ":" not in title:
        return None
    package_part = title.split(":", 1)[0].strip()
    package_name = package_part.split(" ")[0].strip().lower()
    return package_name or None


def _line_range(findings: list[dict]) -> str:
    lines = [f.get("line_start") for f in findings if isinstance(f.get("line_start"), int)]
    if not lines:
        return ""
    low, high = min(lines), max(lines)
    return str(low) if low == high else f"{low}-{high}"


def _vuln_ids(findings: list[dict]) -> list[str]:
    ids: list[str] = []
    for finding in findings:
        title = finding.get("title") or ""
        if ":" in title:
            vuln_id = title.split(":", 1)[1].strip()
            if vuln_id and vuln_id not in ids:
                ids.append(vuln_id)
    return ids


def _pick_best(findings: list[dict], field: str) -> Any:
    for finding in sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity"), 99)):
        value = finding.get(field)
        if value:
            return value
    return None


def _group_to_row(findings: list[dict], repo_fields: dict) -> dict:
    best_severity = min(
        (SEVERITY_ORDER.get(f.get("severity"), 99) for f in findings), default=99
    )
    severity = next(
        (sev for sev, rank in SEVERITY_ORDER.items() if rank == best_severity),
        findings[0].get("severity"),
    )
    source_tools = sorted({f.get("source_tool") for f in findings if f.get("source_tool")})
    category = findings[0].get("category")

    if category == "dependency":
        package = _extract_package_name(findings[0].get("title") or "") or ""
        vuln_ids = _vuln_ids(findings)
        title_summary = f"{package}: {', '.join(vuln_ids)}" if vuln_ids else package
        file_path = ""
        line_range = ""
    else:
        title_summary = _pick_best(findings, "title") or ""
        file_path = findings[0].get("file_path") or ""
        line_range = _line_range(findings)

    return {
        **repo_fields,
        "severity": severity,
        "category": category,
        "file_path": file_path,
        "line_range": line_range,
        "title_summary": title_summary,
        "source_tools": ", ".join(source_tools),
        "finding_count": len(findings),
        "cwe": _pick_best(findings, "cwe"),
        "owasp": _pick_best(findings, "owasp"),
        "description": _pick_best(findings, "description"),
        "recommendation": _pick_best(findings, "recommendation"),
    }


def generate_dedup_csv_report(
    analysis_id: str, findings: list[dict], repository_metadata: dict | None = None
) -> str:
    findings = [as_dict(f) for f in (findings or [])]
    repository_metadata = as_dict(repository_metadata) if repository_metadata else {}
    repo_fields = {
        "repo_url": repository_metadata.get("repo_url"),
        "branch": repository_metadata.get("branch"),
        "commit_sha": repository_metadata.get("commit_sha"),
    }

    groups: dict[tuple, list[dict]] = {}
    for finding in findings:
        key = _group_key(finding)
        groups.setdefault(key, []).append(finding)

    rows = [_group_to_row(group_findings, repo_fields) for group_findings in groups.values()]
    rows.sort(key=lambda r: (SEVERITY_ORDER.get(r["severity"], 99), r["file_path"] or ""))

    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=FIELDNAMES, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return buffer.getvalue()


def write_dedup_csv_report(content: str, output_path: str) -> int:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="")
    return len(content.encode("utf-8"))
