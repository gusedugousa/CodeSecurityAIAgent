"""Internal SARIF-parsing helpers shared by meziantou.py and poutine.py. Not part of the
public tool-adapter contract.

Two dialects are handled separately since their location key names genuinely differ:
- SARIF 2.1.0 (poutine): locations[].physicalLocation.artifactLocation.uri + region.
- MSBuild's SARIF 1.0-ish logger (meziantou, via `dotnet build /p:ErrorLog=`):
  locations[].resultFile.uri, with region nested inside resultFile itself.
Both funnel into the same normalized shape so Finding-dict construction is shared.
"""

from __future__ import annotations

from typing import Any


def parse_sarif_v2_results(data: dict[str, Any]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for run in data.get("runs", []) or []:
        for result in run.get("results", []) or []:
            location = _first(result.get("locations"))
            physical = (location or {}).get("physicalLocation", {})
            artifact = physical.get("artifactLocation", {})
            region = physical.get("region", {})
            normalized.append(
                {
                    "rule_id": result.get("ruleId", "unknown-rule"),
                    "level": result.get("level", "warning"),
                    "message": (result.get("message") or {}).get("text", ""),
                    "file_path": artifact.get("uri"),
                    "line_start": region.get("startLine"),
                    "line_end": region.get("endLine"),
                }
            )
    return normalized


def parse_sarif_msbuild_results(data: dict[str, Any]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for run in data.get("runs", []) or []:
        for result in run.get("results", []) or []:
            location = _first(result.get("locations"))
            result_file = (location or {}).get("resultFile", {})
            region = result_file.get("region", {})
            normalized.append(
                {
                    "rule_id": result.get("ruleId", "unknown-rule"),
                    "level": result.get("level", "warning"),
                    "message": result.get("message", ""),
                    "file_path": _strip_file_uri(result_file.get("uri")),
                    "line_start": region.get("startLine"),
                    "line_end": region.get("endLine"),
                }
            )
    return normalized


def sarif_result_to_finding(
    normalized: dict[str, Any],
    source_tool: str,
    category: str,
    severity_mapping: dict[str, str],
    title_prefix: str = "",
) -> dict[str, Any]:
    severity = severity_mapping.get(normalized["level"], "info")
    return {
        "title": f"{title_prefix}{normalized['rule_id']}",
        "description": normalized.get("message", ""),
        "severity": severity,
        "confidence": "medium",
        "category": category,
        "cwe": None,
        "owasp": None,
        "file_path": normalized.get("file_path"),
        "line_start": normalized.get("line_start"),
        "line_end": normalized.get("line_end"),
        "code_snippet": None,
        "source_tool": source_tool,
        "metadata": {"rule_id": normalized["rule_id"]},
    }


def _first(items: Any) -> dict[str, Any] | None:
    if isinstance(items, list) and items:
        return items[0]
    return None


def _strip_file_uri(uri: str | None) -> str | None:
    if uri is None:
        return None
    return uri.removeprefix("file://")
