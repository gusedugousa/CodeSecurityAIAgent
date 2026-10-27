"""MCP (Model Context Protocol) abstraction layer: adapter interface and null implementation.

Placeholder/extension-point layer only — does not require any live MCP server to run.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from app.core.errors import PlatformError


class MCPNotConfiguredError(PlatformError):
    """Raised when a tool call is attempted against an adapter with no configured MCP server."""

    def __init__(self, message: str, server_name: str | None = None, tool_name: str | None = None) -> None:
        self.server_name = server_name
        self.tool_name = tool_name
        super().__init__(message, code="mcp_not_configured")


@dataclass
class MCPServerConfig:
    """Configuration for a single named MCP server integration."""

    name: str
    server_url: str | None

    @property
    def enabled(self) -> bool:
        return self.server_url is not None and self.server_url != ""


class MCPToolAdapter(ABC):
    """Represents a tool surface exposed via an MCP server."""

    @abstractmethod
    async def list_tools(self) -> list[dict[str, Any]]:
        """Return MCP-style tool descriptors: name, description, input_schema."""
        raise NotImplementedError

    @abstractmethod
    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Invoke a tool by name and return its result."""
        raise NotImplementedError

    @abstractmethod
    def is_configured(self) -> bool:
        """Whether a server URL/credentials are present so this adapter could actually connect."""
        raise NotImplementedError


class NullMCPToolAdapter(MCPToolAdapter):
    """Concrete adapter used when no real MCP server is configured; the MVP default everywhere."""

    def __init__(self, server_name: str = "unknown", server_url: str | None = None) -> None:
        self.server_name = server_name
        self.server_url = server_url

    async def list_tools(self) -> list[dict[str, Any]]:
        return []

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        raise MCPNotConfiguredError(
            f"MCP server '{self.server_name}' is not configured; cannot call tool '{tool_name}'",
            server_name=self.server_name,
            tool_name=tool_name,
        )

    def is_configured(self) -> bool:
        return False
