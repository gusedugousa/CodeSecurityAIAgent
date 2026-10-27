"""Typed exception hierarchy for the platform.

Kept free of framework dependencies (no FastAPI imports) so it can be
imported from any layer; the API layer maps these to HTTP responses.
"""

from __future__ import annotations


class PlatformError(Exception):
    """Base class for all platform-raised errors."""

    def __init__(self, message: str, code: str = "platform_error") -> None:
        self.code = code
        self.message = message
        super().__init__(message)


class ConfigurationError(PlatformError):
    def __init__(self, message: str, config_key: str | None = None) -> None:
        self.config_key = config_key
        super().__init__(message, code="configuration_error")


class ToolExecutionError(PlatformError):
    def __init__(
        self,
        message: str,
        tool_name: str | None = None,
        exit_code: int | None = None,
    ) -> None:
        self.tool_name = tool_name
        self.exit_code = exit_code
        super().__init__(message, code="tool_execution_error")


class ToolNotAvailableError(PlatformError):
    def __init__(self, message: str, tool_name: str | None = None) -> None:
        self.tool_name = tool_name
        super().__init__(message, code="tool_not_available")


class ModelCallError(PlatformError):
    def __init__(
        self,
        message: str,
        role: str | None = None,
        model_name: str | None = None,
    ) -> None:
        self.role = role
        self.model_name = model_name
        super().__init__(message, code="model_call_error")


class RepositoryIngestionError(PlatformError):
    def __init__(
        self,
        message: str,
        repo_url: str | None = None,
        local_path: str | None = None,
    ) -> None:
        self.repo_url = repo_url
        self.local_path = local_path
        super().__init__(message, code="repository_ingestion_error")


class AnalysisNotFoundError(PlatformError):
    def __init__(self, message: str, analysis_id: str | None = None) -> None:
        self.analysis_id = analysis_id
        super().__init__(message, code="analysis_not_found")


class ReportGenerationError(PlatformError):
    def __init__(
        self,
        message: str,
        analysis_id: str | None = None,
        report_type: str | None = None,
    ) -> None:
        self.analysis_id = analysis_id
        self.report_type = report_type
        super().__init__(message, code="report_generation_error")
