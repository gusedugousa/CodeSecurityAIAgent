# MCP Strategy

## Why MCP-ready, not MCP-required

The Model Context Protocol (MCP) is the emerging standard for exposing external systems
(source control, ticketing, vulnerability databases, secrets managers) as callable tools for
AI agents. The final architecture (section 3 of the platform spec) integrates several MCP
servers: GitHub, Azure DevOps, Jira, SonarQube, a vulnerability database, and Vault/secrets.

The MVP does **not** require any live MCP server. Standing up and operating MCP servers is
infrastructure work orthogonal to proving out the agent/orchestration/tooling core. Instead,
the MVP defines the exact interface real MCP clients will implement later, so wiring them in
is additive, not a rewrite.

## The abstraction: `MCPToolAdapter`

`app/mcp/adapter.py` defines:

- `MCPToolAdapter` (ABC) — `list_tools()`, `call_tool(tool_name, arguments)`, `is_configured()`.
- `MCPServerConfig` — name, server_url, and a computed `enabled` flag.
- `NullMCPToolAdapter` — the concrete adapter actually used in the MVP. `list_tools()` returns
  `[]`; `call_tool()` raises `MCPNotConfiguredError` with a clear message; `is_configured()`
  returns `False`. Calling code never crashes when MCP isn't wired up — it just gets an honest
  "not configured" signal.

## Registry

`app/mcp/registry.py` exposes `get_mcp_registry()`, a cached factory returning an `MCPRegistry`
that maps six server names — `github`, `azure_devops`, `jira`, `sonarqube`, `vulnerability_db`,
`vault` — to adapter instances (currently the named placeholder subclasses in
`app/mcp/placeholders.py`, all `NullMCPToolAdapter`-derived). `MCPRegistry.get_status()` reports
which servers have a URL configured via environment variables, so a future health/admin endpoint
can show real-vs-placeholder status per integration.

## Named placeholders

`app/mcp/placeholders.py` — one class per future integration, each documenting its intended
purpose in a single line:

- `GitHubMCPAdapter` — create PRs, read PR metadata, post review comments.
- `AzureDevOpsMCPAdapter` — work item sync, PR creation.
- `JiraMCPAdapter` — create/update tickets from findings.
- `SonarQubeMCPAdapter` — cross-reference findings with quality gate data.
- `VulnerabilityDBMCPAdapter` — enrich findings with live CVE/CWE data.
- `VaultMCPAdapter` — fetch credentials from a secrets manager instead of env vars.

## Wiring in a real MCP client (future work)

To connect a real server: implement a concrete subclass of `MCPToolAdapter` for that server
(using whatever MCP client library/transport is chosen), register it in `MCPRegistry` in place
of the `Null`/placeholder adapter, and set the corresponding `MCP_*_SERVER_URL` environment
variable. No other layer needs to change — agents that eventually call MCP tools do so through
the registry, never against a concrete server implementation.

## Environment variables

`MCP_GITHUB_SERVER_URL`, `MCP_AZURE_DEVOPS_SERVER_URL`, `MCP_JIRA_SERVER_URL`,
`MCP_SONARQUBE_SERVER_URL`, `MCP_VULN_DB_SERVER_URL`, `MCP_VAULT_SERVER_URL` — all unset by
default. Their presence does not currently change MVP behavior; they exist so the registry's
`get_status()` can report which future integrations have a configured target.
