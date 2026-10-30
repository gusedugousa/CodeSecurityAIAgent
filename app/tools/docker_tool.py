"""Placeholder adapter for future container image scanning; disabled by default in tools.yaml."""

from __future__ import annotations

from typing import Any

from app.tools.base import ToolAdapter


class DockerAdapter(ToolAdapter):
    name = "docker"
    category = "container"

    def build_command(self, target_path: str, config: dict[str, Any]) -> list[str]:
        return [self.name, "version", "--format", "{{json .}}"]

    def parse_output(
        self, stdout: str, stderr: str, exit_code: int
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        # Extension point: wire real container/image scanning (e.g. trivy image, docker scout) here.
        return [], {"raw_stdout": stdout, "raw_stderr": stderr, "exit_code": exit_code}
