"""Named placeholder adapters for future MCP server integrations.

Each stores its configured server_url but delegates to NullMCPToolAdapter behavior —
no real client logic yet; that is explicitly out of scope for the MVP.
"""

from __future__ import annotations

from app.mcp.adapter import NullMCPToolAdapter


class GitHubMCPAdapter(NullMCPToolAdapter):
    # future: create PRs, read PR metadata, post review comments via GitHub's MCP server
    def __init__(self, server_url: str | None) -> None:
        super().__init__(server_name="github", server_url=server_url)


class AzureDevOpsMCPAdapter(NullMCPToolAdapter):
    # future: work item sync, PR creation in Azure DevOps
    def __init__(self, server_url: str | None) -> None:
        super().__init__(server_name="azure_devops", server_url=server_url)


class JiraMCPAdapter(NullMCPToolAdapter):
    # future: create/update Jira tickets from findings
    def __init__(self, server_url: str | None) -> None:
        super().__init__(server_name="jira", server_url=server_url)


class SonarQubeMCPAdapter(NullMCPToolAdapter):
    # future: cross-reference findings with SonarQube quality gate data
    def __init__(self, server_url: str | None) -> None:
        super().__init__(server_name="sonarqube", server_url=server_url)


class VulnerabilityDBMCPAdapter(NullMCPToolAdapter):
    # future: enrich findings with live CVE/CWE data from a vulnerability database MCP server
    def __init__(self, server_url: str | None) -> None:
        super().__init__(server_name="vulnerability_db", server_url=server_url)


class VaultMCPAdapter(NullMCPToolAdapter):
    # future: fetch secrets/credentials for scanning contexts from a secrets manager MCP server
    def __init__(self, server_url: str | None) -> None:
        super().__init__(server_name="vault", server_url=server_url)
