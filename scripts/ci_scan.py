"""CI client: submit a repository to a running platform instance, wait, gate on severity.

Usage:
    python scripts/ci_scan.py --url http://localhost:8000 --repo-url https://github.com/o/r \
        --branch main --fail-on high --sarif-out results.sarif

Exit codes: 0 = gate passed, 1 = findings at/above --fail-on,
2 = analysis failed, timed out, or no scanner was available.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import httpx

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
TERMINAL_STATUSES = {"completed", "partial", "failed"}


def gate_failures(findings: list[dict], fail_on: str) -> list[dict]:
    """Findings at or above the threshold, ignoring ones triaged as false positives."""
    threshold = SEVERITY_RANK[fail_on]
    return [
        f
        for f in findings
        if SEVERITY_RANK.get(f.get("severity", "info"), 0) >= threshold
        and f.get("validation_status") != "false_positive"
    ]


def tools_ran(report: dict) -> list[str]:
    return [t["tool_name"] for t in report.get("tool_coverage", []) if t.get("available")]


def run(args: argparse.Namespace) -> int:
    base = args.url.rstrip("/") + "/api/v1"
    payload = {
        "repo_url": args.repo_url,
        "local_path": args.local_path,
        "branch": args.branch,
        "model_profile": args.model_profile,
        "enable_remediation": not args.no_remediation,
    }
    payload = {k: v for k, v in payload.items() if v is not None}

    with httpx.Client(timeout=30) as client:
        analysis_id = client.post(f"{base}/analysis", json=payload).raise_for_status().json()[
            "analysis_id"
        ]
        print(f"analysis {analysis_id} queued")

        deadline = time.monotonic() + args.timeout
        status = "queued"
        while time.monotonic() < deadline:
            info = client.get(f"{base}/analysis/{analysis_id}/status").raise_for_status().json()
            status = info["status"]
            if status in TERMINAL_STATUSES:
                break
            time.sleep(args.poll_interval)
        else:
            print(f"timed out after {args.timeout}s (last status: {status})", file=sys.stderr)
            return 2

        if status == "failed":
            print(f"analysis failed: {info.get('error')}", file=sys.stderr)
            return 2

        if args.sarif_out:
            sarif = client.get(f"{base}/analysis/{analysis_id}/reports/sarif").raise_for_status()
            Path(args.sarif_out).write_bytes(sarif.content)
            print(f"SARIF written to {args.sarif_out}")

        body = client.get(f"{base}/analysis/{analysis_id}/findings").raise_for_status().json()
        report = client.get(f"{base}/analysis/{analysis_id}/reports/json").raise_for_status().json()

    ran = tools_ran(report)
    print(f"scanners that ran: {', '.join(ran) or 'none'}")
    if not ran and not args.allow_no_tools:
        # An empty result from zero scanners is not a clean bill of health.
        print("no scanner was available; refusing to pass the gate", file=sys.stderr)
        return 2

    print(f"severity summary: {body['severity_summary']}")
    failing = gate_failures(body["findings"], args.fail_on)
    for f in failing:
        print(f"  [{f['severity']}] {f['title']} ({f.get('file_path')}:{f.get('line_start')})")
    if failing:
        print(f"gate FAILED: {len(failing)} finding(s) at or above '{args.fail_on}'")
        return 1
    print("gate passed")
    return 0


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--url", default="http://localhost:8000")
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument("--repo-url")
    source.add_argument("--local-path")
    p.add_argument("--branch", default="main")
    p.add_argument("--model-profile", default="default")
    p.add_argument("--no-remediation", action="store_true")
    p.add_argument("--fail-on", choices=list(SEVERITY_RANK), default="high")
    p.add_argument("--allow-no-tools", action="store_true", help="pass even if no scanner ran")
    p.add_argument("--sarif-out")
    p.add_argument("--timeout", type=int, default=900)
    p.add_argument("--poll-interval", type=int, default=5)
    sys.exit(run(p.parse_args()))


if __name__ == "__main__":
    main()
