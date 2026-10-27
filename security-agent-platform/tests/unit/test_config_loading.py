import os

import pytest

from app.core.config import Settings, get_settings


@pytest.fixture(autouse=True)
def _clear_settings_cache():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_settings_loads_yaml_configs():
    settings = Settings()
    assert settings.default_analysis_profile == "mvp-default"
    assert "mvp-default" in settings.analysis_profiles
    assert settings.models["mock_mode"] is True
    assert "semgrep" in settings.tools["tools"]


def test_settings_never_exposes_raw_api_keys():
    settings = Settings()
    assert not hasattr(settings, "openai_api_key")
    assert not hasattr(settings, "anthropic_api_key")
    assert isinstance(settings.provider_credentials_present, dict)


def test_model_mock_mode_env_override(monkeypatch):
    monkeypatch.setenv("MODEL_MOCK_MODE", "false")
    settings = Settings()
    assert settings.models["mock_mode"] is False


def test_get_settings_is_cached():
    a = get_settings()
    b = get_settings()
    assert a is b


def test_mcp_server_urls_default_to_none(monkeypatch):
    # A blank value in a real .env is read as "" by pydantic-settings, not None; assert the
    # falsy/unconfigured contract that app.mcp.registry actually relies on, not a specific type.
    monkeypatch.delenv("MCP_GITHUB_SERVER_URL", raising=False)
    settings = Settings()
    assert not settings.mcp_server_urls["github"]
