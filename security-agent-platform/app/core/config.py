"""Composed application settings: env vars (APP_* + provider/otel vars) merged with configs/*.yaml."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.errors import ConfigurationError


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ConfigurationError(f"missing config file: {path}", config_key=str(path))
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ConfigurationError(f"config file did not parse to a mapping: {path}", config_key=str(path))
    return data


class EnvSettings(BaseSettings):
    """Raw environment-derived values. Only APP_* fields use automatic prefix mapping."""

    model_config = SettingsConfigDict(env_prefix="APP_", env_file=".env", extra="ignore")

    environment: str = "local"
    log_level: str = "INFO"
    storage_backend: str = "sqlite"
    database_url: str = "sqlite+aiosqlite:///./data/security_platform.db"
    redis_url: str = "redis://localhost:6379/0"
    workspace_dir: str = "./data/workspaces"
    reports_dir: str = "./data/reports"


class ProviderEnvSettings(BaseSettings):
    """Provider/otel/mcp env vars that do not use the APP_ prefix.

    Never logged or surfaced in composed Settings beyond presence checks —
    API key values themselves are intentionally not exposed on Settings.
    """

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    openai_api_key: str | None = Field(default=None, alias="OPENAI_API_KEY")
    anthropic_api_key: str | None = Field(default=None, alias="ANTHROPIC_API_KEY")
    google_api_key: str | None = Field(default=None, alias="GOOGLE_API_KEY")
    azure_openai_api_key: str | None = Field(default=None, alias="AZURE_OPENAI_API_KEY")
    azure_openai_endpoint: str | None = Field(default=None, alias="AZURE_OPENAI_ENDPOINT")
    azure_openai_api_version: str | None = Field(default=None, alias="AZURE_OPENAI_API_VERSION")
    ollama_base_url: str | None = Field(default=None, alias="OLLAMA_BASE_URL")

    model_mock_mode: bool | None = Field(default=None, alias="MODEL_MOCK_MODE")

    otel_service_name: str | None = Field(default=None, alias="OTEL_SERVICE_NAME")
    otel_exporter_otlp_endpoint: str | None = Field(default=None, alias="OTEL_EXPORTER_OTLP_ENDPOINT")
    otel_traces_enabled: bool | None = Field(default=None, alias="OTEL_TRACES_ENABLED")
    otel_metrics_enabled: bool | None = Field(default=None, alias="OTEL_METRICS_ENABLED")
    otel_logs_enabled: bool | None = Field(default=None, alias="OTEL_LOGS_ENABLED")

    mcp_github_server_url: str | None = Field(default=None, alias="MCP_GITHUB_SERVER_URL")
    mcp_azure_devops_server_url: str | None = Field(default=None, alias="MCP_AZURE_DEVOPS_SERVER_URL")
    mcp_jira_server_url: str | None = Field(default=None, alias="MCP_JIRA_SERVER_URL")
    mcp_sonarqube_server_url: str | None = Field(default=None, alias="MCP_SONARQUBE_SERVER_URL")
    mcp_vuln_db_server_url: str | None = Field(default=None, alias="MCP_VULN_DB_SERVER_URL")
    mcp_vault_server_url: str | None = Field(default=None, alias="MCP_VAULT_SERVER_URL")


class Settings:
    """Composed, read-only view over env settings + configs/*.yaml."""

    def __init__(self) -> None:
        env = EnvSettings()
        provider_env = ProviderEnvSettings()
        root = _project_root()
        configs_dir = root / "configs"

        app_cfg = _load_yaml(configs_dir / "app.yaml")
        models_cfg = _load_yaml(configs_dir / "models.yaml")
        tools_cfg = _load_yaml(configs_dir / "tools.yaml")
        observability_cfg = _load_yaml(configs_dir / "observability.yaml")

        self.environment: str = env.environment
        self.log_level: str = env.log_level
        self.storage_backend: str = env.storage_backend
        self.database_url: str = env.database_url
        self.redis_url: str = env.redis_url
        self.workspace_dir: str = env.workspace_dir
        self.reports_dir: str = env.reports_dir

        self.default_analysis_profile: str = app_cfg.get(
            "default_analysis_profile", "mvp-default"
        )
        self.analysis_profiles: dict[str, Any] = app_cfg.get("analysis_profiles", {})

        resolved_mock_mode = models_cfg.get("mock_mode", True)
        if provider_env.model_mock_mode is not None:
            resolved_mock_mode = provider_env.model_mock_mode
        self.models: dict[str, Any] = {**models_cfg, "mock_mode": resolved_mock_mode}

        self.tools: dict[str, Any] = tools_cfg

        observability = dict(observability_cfg)
        if provider_env.otel_service_name is not None:
            observability["service_name"] = provider_env.otel_service_name
        if provider_env.otel_exporter_otlp_endpoint is not None:
            observability["otel_endpoint"] = provider_env.otel_exporter_otlp_endpoint
        if provider_env.otel_traces_enabled is not None:
            observability["traces_enabled"] = provider_env.otel_traces_enabled
        if provider_env.otel_metrics_enabled is not None:
            observability["metrics_enabled"] = provider_env.otel_metrics_enabled
        if provider_env.otel_logs_enabled is not None:
            observability["logs_enabled"] = provider_env.otel_logs_enabled
        self.observability: dict[str, Any] = observability

        self.mcp_server_urls: dict[str, str | None] = {
            "github": provider_env.mcp_github_server_url,
            "azure_devops": provider_env.mcp_azure_devops_server_url,
            "jira": provider_env.mcp_jira_server_url,
            "sonarqube": provider_env.mcp_sonarqube_server_url,
            "vuln_db": provider_env.mcp_vuln_db_server_url,
            "vault": provider_env.mcp_vault_server_url,
        }

        self.provider_credentials_present: dict[str, bool] = {
            "openai": bool(provider_env.openai_api_key),
            "anthropic": bool(provider_env.anthropic_api_key),
            "google": bool(provider_env.google_api_key),
            "azure_openai": bool(provider_env.azure_openai_api_key),
        }

        self.ollama_base_url: str = provider_env.ollama_base_url or "http://localhost:11434"
        self.azure_openai_endpoint: str | None = provider_env.azure_openai_endpoint
        self.azure_openai_api_version: str | None = provider_env.azure_openai_api_version

        self.project_root: Path = root


@lru_cache
def get_settings() -> Settings:
    return Settings()
