import time

from fastapi.testclient import TestClient


def test_full_analysis_flow_against_sample_repo(isolated_env):
    from app.main import app

    with TestClient(app) as client:
        health = client.get("/health")
        assert health.status_code == 200

        create = client.post(
            "/api/v1/analysis",
            json={
                "local_path": "tests/fixtures/sample_vulnerable_repo",
                "analysis_profile": "mvp-default",
                "model_profile": "default",
                "enable_remediation": True,
            },
        )
        assert create.status_code == 202
        analysis_id = create.json()["analysis_id"]
        assert create.json()["status"] == "queued"

        final_status = None
        for _ in range(50):
            status_resp = client.get(f"/api/v1/analysis/{analysis_id}/status")
            assert status_resp.status_code == 200
            final_status = status_resp.json()
            if final_status["status"] in ("completed", "failed", "partial"):
                break
            time.sleep(0.2)

        assert final_status is not None
        assert final_status["status"] == "completed"

        findings_resp = client.get(f"/api/v1/analysis/{analysis_id}/findings")
        assert findings_resp.status_code == 200
        findings_body = findings_resp.json()
        assert findings_body["analysis_id"] == analysis_id
        assert isinstance(findings_body["findings"], list)
        assert "severity_summary" in findings_body

        json_report = client.get(f"/api/v1/analysis/{analysis_id}/reports/json")
        assert json_report.status_code == 200
        assert json_report.headers["content-type"].startswith("application/json")

        md_report = client.get(f"/api/v1/analysis/{analysis_id}/reports/markdown")
        assert md_report.status_code == 200
        assert b"Executive Summary" in md_report.content

        sarif_report = client.get(f"/api/v1/analysis/{analysis_id}/reports/sarif")
        assert sarif_report.status_code == 200
        assert b'"version": "2.1.0"' in sarif_report.content

        csv_report = client.get(f"/api/v1/analysis/{analysis_id}/reports/csv")
        assert csv_report.status_code == 200
        assert csv_report.headers["content-type"].startswith("text/csv")
        header_line = csv_report.content.decode("utf-8").splitlines()[0]
        assert "source_tool" in header_line
        assert "source_agent" in header_line


def test_status_for_unknown_analysis_returns_404(isolated_env):
    from app.main import app

    with TestClient(app) as client:
        resp = client.get("/api/v1/analysis/does-not-exist/status")
        assert resp.status_code == 404
        assert resp.json()["code"] == "analysis_not_found"


def test_create_analysis_requires_repo_url_or_local_path(isolated_env):
    from app.main import app

    with TestClient(app) as client:
        resp = client.post("/api/v1/analysis", json={"branch": "main"})
        assert resp.status_code == 422
