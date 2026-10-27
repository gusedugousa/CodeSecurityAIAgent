import pytest

from app.agents.cicd_agent import CICDAgent


@pytest.mark.asyncio
async def test_cicd_agent_skips_when_no_local_repo_path():
    agent = CICDAgent()
    state = {"analysis_id": "test", "tools_config": {}, "warnings": [], "errors": []}
    result = await agent.run(state)
    assert any("no local_repo_path" in w for w in result["warnings"])
    assert result.get("findings", []) == []


@pytest.mark.asyncio
async def test_cicd_agent_runs_poutine_and_reports_unavailable_gracefully(tmp_path):
    agent = CICDAgent()
    state = {
        "analysis_id": "test",
        "local_repo_path": str(tmp_path),
        "tools_config": {"tools": {}, "defaults": {"timeout_seconds": 5}},
        "warnings": [],
        "errors": [],
        "findings": [],
        "tool_results": [],
    }
    result = await agent.run(state)
    assert result["errors"] == []
    # poutine may or may not be installed in the test environment; either way this
    # must never raise, and must produce a tool_results entry for "poutine".
    tool_names = [t["tool_name"] for t in result["tool_results"]]
    assert "poutine" in tool_names
