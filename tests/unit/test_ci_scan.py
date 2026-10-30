import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "ci_scan", Path(__file__).resolve().parents[2] / "scripts" / "ci_scan.py"
)
ci_scan = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ci_scan)


def test_gate_flags_findings_at_or_above_threshold():
    findings = [
        {"severity": "critical", "title": "a"},
        {"severity": "high", "title": "b"},
        {"severity": "medium", "title": "c"},
    ]
    assert [f["title"] for f in ci_scan.gate_failures(findings, "high")] == ["a", "b"]


def test_gate_ignores_false_positives():
    findings = [{"severity": "critical", "validation_status": "false_positive"}]
    assert ci_scan.gate_failures(findings, "low") == []


def test_tools_ran_lists_only_available_scanners():
    report = {"tool_coverage": [{"tool_name": "bandit", "available": True},
                                {"tool_name": "semgrep", "available": False}]}
    assert ci_scan.tools_ran(report) == ["bandit"]
    assert ci_scan.tools_ran({}) == []
