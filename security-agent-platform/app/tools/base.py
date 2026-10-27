"""Base abstraction all security tool adapters implement."""

from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from typing import Any


class ToolAdapter(ABC):
    name: str
    category: str

    def is_available(self) -> bool:
        return shutil.which(self.name) is not None

    def has_scannable_target(self, target_path: str) -> bool:
        """Whether target_path actually contains something this tool can meaningfully scan.

        Default True (most scanners walk the whole tree and are safe to always run).
        Override for tools that fall back to auditing unrelated state (e.g. pip-audit
        auditing the running interpreter) when no relevant project files are present.
        """
        return True

    @abstractmethod
    def build_command(self, target_path: str, config: dict[str, Any]) -> list[str]:
        """Build the CLI invocation (argv list) for this tool against target_path."""

    @abstractmethod
    def parse_output(
        self, stdout: str, stderr: str, exit_code: int
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """Normalize raw tool output into (finding dicts, raw_metadata).

        Finding dicts carry Finding-shaped keys minus id/created_at/source_agent
        (those are filled in by the calling agent). Must never raise on
        malformed/empty output — fall back to preserving raw output in metadata.
        """
