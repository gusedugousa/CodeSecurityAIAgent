"""In-memory registry of named MCP server adapters."""

from __future__ import annotations

import os
from functools import lru_cache

from app.mcp.adapter import MCPServerConfig, MCPToolAdapter
from app.mcp.placeholders import (
    AzureDevOpsMCPAdapter,
    GitHubMCPAdapter,
    JiraMCPAdapter,
    SonarQubeMCPAdapter,
    VaultMCPAdapter,
    VulnerabilityDBMCPAdapter,
)

_SERVER_ENV_VARS: dict[str, str] = {
    "github": "MCP_GITHUB_SERVER_URL",
    "azure_devops": "MCP_AZURE_DEVOPS_SERVER_URL",
    "jira": "MCP_JIRA_SERVER_URL",
    "sonarqube": "MCP_SONARQUBE_SERVER_URL",
    "vulnerability_db": "MCP_VULN_DB_SERVER_URL",
    "vault": "MCP_VAULT_SERVER_URL",
}


class MCPRegistry:
    """Maps MCP server names to MCPToolAdapter instances.

    MVP always registers the named placeholder adapters (which behave like
    NullMCPToolAdapter) regardless of whether a server URL is configured —
    the point is the registry shape is ready, not that it connects.
    """

    def __init__(self) -> None:
        self._configs: dict[str, MCPServerConfig] = {
            name: MCPServerConfig(name=name, server_url=os.environ.get(env_var) or None)
            for name, env_var in _SERVER_ENV_VARS.items()
        }

        self._adapters: dict[str, MCPToolAdapter] = {
            "github": GitHubMCPAdapter(self._configs["github"].server_url),
            "azure_devops": AzureDevOpsMCPAdapter(self._configs["azure_devops"].server_url),
            "jira": JiraMCPAdapter(self._configs["jira"].server_url),
            "sonarqube": SonarQubeMCPAdapter(self._configs["sonarqube"].server_url),
            "vulnerability_db": VulnerabilityDBMCPAdapter(self._configs["vulnerability_db"].server_url),
            "vault": VaultMCPAdapter(self._configs["vault"].server_url),
        }

    def get(self, name: str) -> MCPToolAdapter:
        try:
            return self._adapters[name]
        except KeyError as exc:
            raise KeyError(
                f"unknown MCP server '{name}'; registered servers: {self.list_registered()}"
            ) from exc

    def list_registered(self) -> list[str]:
        return list(self._adapters.keys())

    def get_status(self) -> dict[str, bool]:
        return {name: adapter.is_configured() for name, adapter in self._adapters.items()}


@lru_cache
def get_mcp_registry() -> MCPRegistry:
    return MCPRegistry()
