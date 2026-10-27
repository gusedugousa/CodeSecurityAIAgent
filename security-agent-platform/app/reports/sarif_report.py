# Known SARIF limitations of this generator (not a fully certified SARIF 2.1.0 producer):
# - No ruleId taxonomy validation against an external taxonomy/index.
# - No originalUriBaseIds; artifactLocation.uri is used as-is (no base URI resolution).
# - No partial fingerprinting or result baselining/matching support across runs.
# - level mapping (error/warning/note) is a simplification of SARIF's full severity/rank model.
# - No support for multi-tool "runs" merging or invocation/notification objects.

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import json
import re

from app.reports._shared import as_dict

SARIF_SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
TOOL_NAME = "security-agent-platform"
TOOL_VERSION = "0.1.0"
TOOL_INFO_URI = "https://github.com/example-org/security-agent-platform"

_LEVEL_BY_SEVERITY = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip().lower()).strip("-")
    return slug or "unknown"


def _rule_id(finding: dict) -> str:
    source_tool = finding.get("source_tool") or "unknown-tool"
    category = finding.get("category") or "uncategorized"
    return f"{_slugify(source_tool)}.{_slugify(category)}"


def _build_rules(findings: list[dict]) -> list[dict]:
    rules: dict[str, dict] = {}
    for finding in findings:
        rule_id = _rule_id(finding)
        if rule_id in rules:
            continue
        category = finding.get("category") or "uncategorized"
        source_tool = finding.get("source_tool") or "unknown-tool"
        rules[rule_id] = {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {
                "text": f"{category} findings reported by {source_tool}",
            },
        }
    return list(rules.values())


def _build_result(finding: dict, analysis_id: str) -> dict:
    severity = finding.get("severity")
    level = _LEVEL_BY_SEVERITY.get(severity, "warning")
    result: dict[str, Any] = {
        "ruleId": _rule_id(finding),
        "level": level,
        "message": {"text": finding.get("description") or finding.get("title") or ""},
    }
    file_path = finding.get("file_path")
    if file_path:
        region: dict[str, Any] = {}
        if finding.get("line_start") is not None:
            region["startLine"] = finding.get("line_start")
        if finding.get("line_end") is not None:
            region["endLine"] = finding.get("line_end")
        physical_location: dict[str, Any] = {"artifactLocation": {"uri": file_path}}
        if region:
            physical_location["region"] = region
        result["locations"] = [{"physicalLocation": physical_location}]
    result["properties"] = {
        "severity": finding.get("severity"),
        "confidence": finding.get("confidence"),
        "cwe": finding.get("cwe"),
        "owasp": finding.get("owasp"),
        "source_agent": finding.get("source_agent"),
        "analysis_id": analysis_id,
    }
    return result


def _repo_properties(repository_metadata: dict | None) -> dict[str, Any]:
    # SARIF has no standard "scanned repository" slot (it's a per-file/per-result
    # format, not per-repo) - run.properties is the spec-sanctioned extension point
    # for tool-specific metadata, so repo identity goes there.
    if not repository_metadata:
        return {}
    return {
        "repo_url": repository_metadata.get("repo_url"),
        "branch": repository_metadata.get("branch"),
        "commit_sha": repository_metadata.get("commit_sha"),
        "local_path": repository_metadata.get("local_path"),
    }


def generate_sarif_report(
    analysis_id: str,
    findings: list[dict],
    repository_metadata: dict | None,
    tool_results: list[dict],
    generated_at: datetime | None = None,
) -> dict:
    findings = [as_dict(f) for f in (findings or [])]
    repository_metadata = as_dict(repository_metadata) if repository_metadata else None
    _ = [as_dict(t) for t in (tool_results or [])]
    _ = generated_at or datetime.now(timezone.utc)

    rules = _build_rules(findings)
    results = [_build_result(f, analysis_id) for f in findings]

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "version": TOOL_VERSION,
                "informationUri": TOOL_INFO_URI,
                "rules": rules,
            }
        },
        "results": results,
    }
    repo_properties = _repo_properties(repository_metadata)
    if repo_properties:
        run["properties"] = repo_properties

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": "2.1.0",
        "runs": [run],
    }


def write_sarif_report(report: dict, output_path: str) -> int:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(report, indent=2, default=str)
    path.write_text(content, encoding="utf-8")
    return len(content.encode("utf-8"))
