import csv
import io

from app.reports.csv_report import generate_csv_report
from app.reports.dedup_csv_report import generate_dedup_csv_report
from app.reports.json_report import generate_json_report
from app.reports.markdown_report import generate_markdown_report
from app.reports.sarif_report import generate_sarif_report

FINDINGS = [
    {
        "id": "f1",
        "title": "SQL Injection",
        "description": "User input concatenated into query",
        "severity": "critical",
        "confidence": "high",
        "category": "sast",
        "cwe": "CWE-89",
        "owasp": "A03:2021",
        "file_path": "app.py",
        "line_start": 10,
        "line_end": 10,
        "code_snippet": "query = 'SELECT * FROM x WHERE id=' + user_id",
        "evidence": [{"description": "raw query build", "snippet": None, "source": "semgrep"}],
        "attack_scenario": "Attacker injects OR 1=1",
        "business_impact": "Data breach",
        "recommendation": "Use parameterized queries",
        "remediation": None,
        "source_tool": "semgrep",
        "source_agent": "sast",
        "validation_status": "unvalidated",
        "false_positive_reason": None,
        "created_at": "2026-07-02T00:00:00Z",
    },
    {
        "id": "f2",
        "title": "Missing file path finding",
        "description": "Dependency-level issue",
        "severity": "medium",
        "confidence": "medium",
        "category": "dependency",
        "cwe": None,
        "owasp": None,
        "file_path": None,
        "line_start": None,
        "line_end": None,
        "code_snippet": None,
        "evidence": [],
        "attack_scenario": None,
        "business_impact": None,
        "recommendation": None,
        "remediation": None,
        "source_tool": "pip_audit",
        "source_agent": "dependency",
        "validation_status": "unvalidated",
        "false_positive_reason": None,
        "created_at": "2026-07-02T00:00:00Z",
    },
]

TOOL_RESULTS = [
    {"tool_name": "semgrep", "category": "sast", "available": True, "findings_count": 1},
    {"tool_name": "trivy", "category": "dependency", "available": False, "findings_count": 0},
]

SEVERITY_SUMMARY = {"critical": 1, "high": 0, "medium": 1, "low": 0, "info": 0, "total": 2}


def test_json_report_includes_all_findings_and_tool_coverage():
    report = generate_json_report(
        analysis_id="abc123",
        findings=FINDINGS,
        repository_metadata={"repo_url": "https://example.com/repo.git", "branch": "main"},
        severity_summary=SEVERITY_SUMMARY,
        tool_results=TOOL_RESULTS,
        warnings=["trivy not installed"],
    )
    assert report["analysis_id"] == "abc123"
    assert len(report["findings"]) == 2
    assert "trivy" in report["tools_unavailable"]
    assert report["severity_summary"]["critical"] == 1


def test_json_report_handles_empty_findings():
    report = generate_json_report(
        analysis_id="empty",
        findings=[],
        repository_metadata=None,
        severity_summary=None,
        tool_results=[],
        warnings=[],
    )
    assert report["findings"] == []
    assert report["tools_unavailable"] == []


def test_markdown_report_contains_required_sections():
    md = generate_markdown_report(
        analysis_id="abc123",
        findings=FINDINGS,
        repository_metadata={"repo_url": "https://example.com/repo.git", "branch": "main"},
        severity_summary=SEVERITY_SUMMARY,
        tool_results=TOOL_RESULTS,
        executive_summary="Two findings identified.",
        warnings=["trivy not installed"],
    )
    assert "# " in md
    assert "Executive Summary" in md
    assert "Repository Metadata" in md
    assert "Severity Summary" in md
    assert "Findings" in md
    assert "Tool Coverage" in md
    assert "Tools Unavailable" in md
    assert "SQL Injection" in md
    assert "trivy" in md


def test_markdown_report_handles_no_findings():
    md = generate_markdown_report(
        analysis_id="empty",
        findings=[],
        repository_metadata=None,
        severity_summary=None,
        tool_results=[],
        executive_summary=None,
        warnings=[],
    )
    assert "No findings" in md or "no findings" in md.lower()


def test_markdown_report_escapes_pipe_in_title():
    findings = [dict(FINDINGS[0])]
    findings[0] = {**findings[0], "title": "Weird | Title"}
    md = generate_markdown_report(
        analysis_id="x",
        findings=findings,
        repository_metadata=None,
        severity_summary=SEVERITY_SUMMARY,
        tool_results=[],
        executive_summary=None,
        warnings=[],
    )
    assert "Weird \\| Title" in md


def test_sarif_report_structure():
    sarif = generate_sarif_report(
        analysis_id="abc123",
        findings=FINDINGS,
        repository_metadata={"repo_url": "https://example.com/repo.git"},
        tool_results=TOOL_RESULTS,
    )
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"]
    assert len(run["results"]) == 2
    critical_result = next(r for r in run["results"] if r["properties"]["severity"] == "critical")
    assert critical_result["level"] == "error"
    assert critical_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app.py"


def test_sarif_report_omits_locations_when_file_path_missing():
    sarif = generate_sarif_report(
        analysis_id="abc123",
        findings=[FINDINGS[1]],
        repository_metadata=None,
        tool_results=[],
    )
    result = sarif["runs"][0]["results"][0]
    assert not result.get("locations")


def test_sarif_report_handles_empty_findings():
    sarif = generate_sarif_report(
        analysis_id="empty", findings=[], repository_metadata=None, tool_results=[]
    )
    assert sarif["runs"][0]["results"] == []


def _read_csv_rows(csv_text: str) -> list[dict]:
    return list(csv.DictReader(io.StringIO(csv_text)))


def test_csv_report_has_one_row_per_finding_with_tool_and_agent_columns():
    content = generate_csv_report(analysis_id="abc123", findings=FINDINGS)
    rows = _read_csv_rows(content)
    assert len(rows) == 2
    assert {r["source_tool"] for r in rows} == {"semgrep", "pip_audit"}
    assert {r["source_agent"] for r in rows} == {"sast", "dependency"}
    assert rows[0]["severity"] == "critical"


def test_csv_report_includes_remediation_columns():
    finding_with_remediation = {
        **FINDINGS[0],
        "remediation": {
            "finding_id": "f1",
            "summary": "Use parameterized queries",
            "patch_diff": "- bad\n+ good",
            "explanation": "Avoids SQL injection",
            "generated_by_model": "anthropic/claude-sonnet-4",
        },
    }
    content = generate_csv_report(analysis_id="abc123", findings=[finding_with_remediation])
    rows = _read_csv_rows(content)
    assert rows[0]["remediation_summary"] == "Use parameterized queries"
    assert rows[0]["remediation_generated_by_model"] == "anthropic/claude-sonnet-4"


def test_csv_report_handles_empty_findings():
    content = generate_csv_report(analysis_id="empty", findings=[])
    rows = _read_csv_rows(content)
    assert rows == []
    assert "source_tool" in content.splitlines()[0]


def test_csv_report_sorted_by_severity():
    content = generate_csv_report(analysis_id="abc123", findings=FINDINGS)
    rows = _read_csv_rows(content)
    assert rows[0]["severity"] == "critical"
    assert rows[1]["severity"] == "medium"


def test_csv_report_includes_repo_columns():
    content = generate_csv_report(
        analysis_id="abc123",
        findings=FINDINGS,
        repository_metadata={
            "repo_url": "https://example.com/repo.git",
            "branch": "main",
            "commit_sha": "abc123def",
        },
    )
    rows = _read_csv_rows(content)
    assert rows[0]["repo_url"] == "https://example.com/repo.git"
    assert rows[0]["branch"] == "main"
    assert rows[0]["commit_sha"] == "abc123def"


def test_sarif_report_includes_repo_in_run_properties():
    sarif = generate_sarif_report(
        analysis_id="abc123",
        findings=FINDINGS,
        repository_metadata={
            "repo_url": "https://example.com/repo.git",
            "branch": "main",
            "commit_sha": "abc123def",
            "local_path": "/scan-targets/repo",
        },
        tool_results=[],
    )
    props = sarif["runs"][0]["properties"]
    assert props["repo_url"] == "https://example.com/repo.git"
    assert props["branch"] == "main"
    assert props["local_path"] == "/scan-targets/repo"


def test_sarif_report_omits_properties_when_no_repo_metadata():
    sarif = generate_sarif_report(
        analysis_id="abc123", findings=FINDINGS, repository_metadata=None, tool_results=[]
    )
    assert "properties" not in sarif["runs"][0]


def test_markdown_report_includes_local_path():
    md = generate_markdown_report(
        analysis_id="abc123",
        findings=FINDINGS,
        repository_metadata={"repo_url": None, "local_path": "/scan-targets/repo", "branch": "main"},
        severity_summary=SEVERITY_SUMMARY,
        tool_results=[],
        executive_summary=None,
        warnings=[],
    )
    assert "/scan-targets/repo" in md


# --- Deduplicated CSV report ---
# Grouping cases below mirror a real captured duplicate: semgrep + bandit both
# flagging tests/fixtures/.../scripts/changelog.py:232 as separate findings with
# unrelated titles/CWEs (CWE-939 vs CWE-22) - same file+line, different tool.

_SAST_DUPLICATE_FINDINGS = [
    {
        **FINDINGS[0],
        "id": "dup-1",
        "title": "python.lang.security.audit.dynamic-urllib-use-detected",
        "severity": "medium",
        "category": "sast",
        "cwe": "CWE-939",
        "file_path": "scripts/changelog.py",
        "line_start": 232,
        "line_end": 232,
        "source_tool": "semgrep",
    },
    {
        **FINDINGS[0],
        "id": "dup-2",
        "title": "blacklist",
        "severity": "high",
        "category": "sast",
        "cwe": "CWE-22",
        "file_path": "scripts/changelog.py",
        "line_start": 232,
        "line_end": 232,
        "source_tool": "bandit",
    },
]

_DEPENDENCY_DUPLICATE_FINDINGS = [
    {
        **FINDINGS[1],
        "id": "dep-1",
        "title": "requests 2.25.0: GHSA-abcd",
        "severity": "high",
        "category": "dependency",
        "source_tool": "pip_audit",
    },
    {
        **FINDINGS[1],
        "id": "dep-2",
        "title": "requests: GHSA-abcd",
        "severity": "high",
        "category": "dependency",
        "source_tool": "osv_scanner",
    },
    {
        **FINDINGS[1],
        "id": "dep-3",
        "title": "requests: CVE-2023-99999",
        "severity": "critical",
        "category": "dependency",
        "source_tool": "trivy",
    },
]


def test_dedup_csv_collapses_sast_findings_at_same_file_and_line():
    content = generate_dedup_csv_report(analysis_id="abc123", findings=_SAST_DUPLICATE_FINDINGS)
    rows = _read_csv_rows(content)
    assert len(rows) == 1
    row = rows[0]
    assert row["file_path"] == "scripts/changelog.py"
    assert row["line_range"] == "232"
    assert row["finding_count"] == "2"
    assert row["source_tools"] == "bandit, semgrep"
    # Best (highest) severity across the group wins.
    assert row["severity"] == "high"


def test_dedup_csv_collapses_dependency_findings_by_package_name():
    content = generate_dedup_csv_report(
        analysis_id="abc123", findings=_DEPENDENCY_DUPLICATE_FINDINGS
    )
    rows = _read_csv_rows(content)
    assert len(rows) == 1
    row = rows[0]
    assert row["finding_count"] == "3"
    assert row["source_tools"] == "osv_scanner, pip_audit, trivy"
    assert row["severity"] == "critical"
    assert "requests" in row["title_summary"]
    assert "GHSA-abcd" in row["title_summary"]
    assert "CVE-2023-99999" in row["title_summary"]


def test_dedup_csv_does_not_merge_unrelated_findings():
    content = generate_dedup_csv_report(analysis_id="abc123", findings=FINDINGS)
    rows = _read_csv_rows(content)
    # FINDINGS has one sast finding with a file_path and one dependency finding with
    # no file_path/package-parseable title - neither shares a grouping anchor with
    # anything else, so both remain as separate, unmerged rows.
    assert len(rows) == 2
    assert all(int(r["finding_count"]) == 1 for r in rows)


def test_dedup_csv_handles_empty_findings():
    content = generate_dedup_csv_report(analysis_id="empty", findings=[])
    rows = _read_csv_rows(content)
    assert rows == []
    assert "source_tools" in content.splitlines()[0]


def test_dedup_csv_includes_repo_columns():
    content = generate_dedup_csv_report(
        analysis_id="abc123",
        findings=_SAST_DUPLICATE_FINDINGS,
        repository_metadata={"repo_url": "https://example.com/repo.git", "branch": "main"},
    )
    rows = _read_csv_rows(content)
    assert rows[0]["repo_url"] == "https://example.com/repo.git"
    assert rows[0]["branch"] == "main"
