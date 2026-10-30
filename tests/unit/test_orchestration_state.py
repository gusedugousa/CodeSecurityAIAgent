from app.core.config import Settings
from app.orchestration.state import create_initial_state


def test_create_initial_state_from_repo_url_request():
    settings = Settings()
    request = {
        "repo_url": "https://github.com/example/repo.git",
        "branch": "main",
        "analysis_profile": "mvp-default",
        "model_profile": "default",
        "enable_remediation": True,
    }
    state = create_initial_state("abc123", request, settings)

    assert state["analysis_id"] == "abc123"
    assert state["repo_url"] == "https://github.com/example/repo.git"
    assert state["local_repo_path"] is None
    assert state["findings"] == []
    assert state["errors"] == []
    assert state["fatal_error"] is False
    assert state["status"] == "queued"
    assert state["mock_mode"] is True


def test_create_initial_state_defaults_enable_remediation_from_profile():
    settings = Settings()
    request = {"local_path": "/tmp/some-repo", "analysis_profile": "fast-scan"}
    state = create_initial_state("xyz", request, settings)
    assert state["enable_remediation"] is False


def test_create_initial_state_falls_back_to_default_profile_for_unknown_profile():
    settings = Settings()
    request = {"local_path": "/tmp/some-repo", "analysis_profile": "totally-unknown-profile"}
    state = create_initial_state("xyz", request, settings)
    assert state["analysis_profile"] == "totally-unknown-profile"
    assert state["enable_remediation"] is True
