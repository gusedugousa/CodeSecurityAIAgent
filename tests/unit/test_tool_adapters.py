import json
import os

from app.tools.bandit import BanditAdapter
from app.tools.meziantou import MeziantouAnalyzerAdapter
from app.tools.poutine import PoutineAdapter
from app.tools.semgrep import SemgrepAdapter, SemgrepDatabricksAdapter


def test_semgrep_parses_valid_json():
    adapter = SemgrepAdapter()
    stdout = json.dumps(
        {
            "results": [
                {
                    "check_id": "python.lang.security.sql-injection",
                    "path": "app.py",
                    "start": {"line": 10},
                    "end": {"line": 10},
                    "extra": {
                        "message": "SQL injection risk",
                        "severity": "ERROR",
                        "lines": "query = 'SELECT * FROM x WHERE id=' + user_id",
                        "metadata": {"cwe": ["CWE-89"], "owasp": ["A03:2021"]},
                    },
                }
            ],
            "errors": [],
        }
    )
    findings, metadata = adapter.parse_output(stdout, "", 0)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["severity"] == "critical"
    assert finding["file_path"] == "app.py"
    assert finding["cwe"] == "CWE-89"
    assert finding["source_tool"] == "semgrep"


def test_semgrep_handles_malformed_json_without_raising():
    adapter = SemgrepAdapter()
    findings, metadata = adapter.parse_output("not json {{{", "some stderr", 1)
    assert findings == []
    assert metadata["parse_error"] == "invalid_json"
    assert metadata["raw_stdout"] == "not json {{{"


def test_semgrep_handles_empty_output():
    adapter = SemgrepAdapter()
    findings, metadata = adapter.parse_output("", "", 0)
    assert findings == []


def test_bandit_parses_valid_json():
    adapter = BanditAdapter()
    stdout = json.dumps(
        {
            "results": [
                {
                    "test_id": "B105",
                    "test_name": "hardcoded_password_string",
                    "filename": "app.py",
                    "line_number": 5,
                    "issue_severity": "MEDIUM",
                    "issue_confidence": "HIGH",
                    "issue_text": "Possible hardcoded password",
                    "code": "PASSWORD = 'hunter2'\n",
                }
            ]
        }
    )
    findings, _ = adapter.parse_output(stdout, "", 1)
    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"
    assert findings[0]["source_tool"] == "bandit"


def test_bandit_handles_malformed_json_without_raising():
    adapter = BanditAdapter()
    findings, metadata = adapter.parse_output("<<not json>>", "", 2)
    assert findings == []
    assert "parse_error" in metadata or "raw_stdout" in metadata


def test_adapter_name_and_category_set():
    assert SemgrepAdapter().name == "semgrep"
    assert SemgrepAdapter().category == "sast"
    assert BanditAdapter().name == "bandit"
    assert BanditAdapter().category == "sast"
    assert MeziantouAnalyzerAdapter().name == "meziantou"
    assert MeziantouAnalyzerAdapter().category == "sast"
    assert PoutineAdapter().name == "poutine"
    assert PoutineAdapter().category == "cicd"
    assert SemgrepDatabricksAdapter().name == "semgrep_databricks"
    assert SemgrepDatabricksAdapter().category == "iac"


def test_poutine_parses_sarif_v2_output():
    adapter = PoutineAdapter()
    stdout = json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "unverified_script_exec",
                            "level": "note",
                            "message": {"text": "curl | bash detected"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "azure-pipelines.yml"},
                                        "region": {"startLine": 8, "endLine": 8},
                                    }
                                }
                            ],
                        }
                    ]
                }
            ],
        }
    )
    findings, metadata = adapter.parse_output(stdout, "", 0)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["source_tool"] == "poutine"
    assert finding["category"] == "cicd"
    assert finding["severity"] == "medium"
    assert finding["file_path"] == "azure-pipelines.yml"
    assert finding["line_start"] == 8
    assert "unverified_script_exec" in finding["title"]


def test_poutine_handles_malformed_json_without_raising():
    adapter = PoutineAdapter()
    findings, metadata = adapter.parse_output("not json", "", 1)
    assert findings == []
    assert metadata["parse_error"] == "invalid_json"


def test_poutine_handles_empty_output():
    adapter = PoutineAdapter()
    findings, _ = adapter.parse_output("", "", 0)
    assert findings == []


def test_meziantou_parses_msbuild_sarif_dialect():
    adapter = MeziantouAnalyzerAdapter()
    stdout = json.dumps(
        {
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "CS0246",
                            "level": "error",
                            "message": "compiler error, not a security finding",
                            "locations": [
                                {"resultFile": {"uri": "file:///tmp/x/Program.cs"}}
                            ],
                        },
                        {
                            "ruleId": "MA0026",
                            "level": "warning",
                            "message": "TODO comment found",
                            "locations": [
                                {
                                    "resultFile": {
                                        "uri": "file:///tmp/x/Service.cs",
                                        "region": {"startLine": 12, "endLine": 12},
                                    }
                                }
                            ],
                        },
                    ]
                }
            ]
        }
    )
    # simulate parse_output being called after build_command wrote a real sarif file
    fd_path = "/tmp/test_meziantou_fixture.sarif"
    with open(fd_path, "w", encoding="utf-8") as fh:
        fh.write(stdout)
    adapter._sarif_path = fd_path
    findings, metadata = adapter.parse_output("", "", 0)

    # Only the MA-prefixed analyzer result should surface; CS compiler errors are filtered out.
    assert len(findings) == 1
    finding = findings[0]
    assert finding["source_tool"] == "meziantou"
    assert finding["category"] == "sast"
    assert finding["severity"] == "medium"
    assert finding["file_path"] == "/tmp/x/Service.cs"
    assert finding["line_start"] == 12
    assert "MA0026" in finding["title"]
    assert not os.path.isfile(fd_path)  # cleaned up by parse_output


def test_meziantou_handles_missing_sarif_file_without_raising():
    adapter = MeziantouAnalyzerAdapter()
    adapter._sarif_path = "/tmp/does-not-exist-meziantou.sarif"
    findings, metadata = adapter.parse_output("some stdout", "some stderr", 1)
    assert findings == []
    assert metadata["parse_error"] == "no_sarif_output"


def test_meziantou_has_scannable_target_requires_csproj_or_sln(tmp_path):
    adapter = MeziantouAnalyzerAdapter()
    assert adapter.has_scannable_target(str(tmp_path)) is False
    (tmp_path / "Project.csproj").write_text("<Project></Project>")
    assert adapter.has_scannable_target(str(tmp_path)) is True


def test_semgrep_databricks_forces_iac_category_and_prefixes_title():
    adapter = SemgrepDatabricksAdapter()
    stdout = json.dumps(
        {
            "results": [
                {
                    "check_id": "databricks-hardcoded-secret-in-bundle-var",
                    "path": "databricks.yml",
                    "start": {"line": 5},
                    "end": {"line": 6},
                    "extra": {"message": "hardcoded secret", "severity": "ERROR"},
                }
            ],
            "errors": [],
        }
    )
    findings, _ = adapter.parse_output(stdout, "", 0)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["category"] == "iac"
    assert finding["source_tool"] == "semgrep"
    assert finding["title"].startswith("[databricks] ")


def test_semgrep_databricks_has_scannable_target_requires_databricks_yml(tmp_path):
    adapter = SemgrepDatabricksAdapter()
    assert adapter.has_scannable_target(str(tmp_path)) is False
    (tmp_path / "databricks.yml").write_text("bundle:\n  name: x\n")
    assert adapter.has_scannable_target(str(tmp_path)) is True
