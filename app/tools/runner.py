"""Executes ToolAdapters as subprocesses without ever raising out of the run."""

from __future__ import annotations

import asyncio
import shlex
from datetime import UTC, datetime
from typing import Any

from app.tools.base import ToolAdapter


def _now() -> datetime:
    return datetime.now(UTC)


class ToolRunner:
    def __init__(self, adapter: ToolAdapter) -> None:
        self.adapter = adapter

    async def run(self, target_path: str, config: dict[str, Any]) -> dict[str, Any]:
        started_at = _now()
        tool_config = config.get("tools", {}).get(self.adapter.name, {})
        default_timeout = config.get("defaults", {}).get("timeout_seconds", 300)
        timeout_seconds = tool_config.get("timeout_seconds", default_timeout)

        if not self.adapter.is_available():
            return self._result(
                available=False,
                command=None,
                exit_code=None,
                stdout=None,
                stderr=None,
                duration_ms=0.0,
                started_at=started_at,
                findings_count=0,
                error="tool not installed",
                raw_output_parsed=False,
            )

        if not self.adapter.has_scannable_target(target_path):
            return self._result(
                available=True,
                command=None,
                exit_code=None,
                stdout=None,
                stderr=None,
                duration_ms=0.0,
                started_at=started_at,
                findings_count=0,
                error="no scannable target for this tool in the given path, skipped",
                raw_output_parsed=False,
            )

        try:
            argv = self.adapter.build_command(target_path, tool_config)
        except Exception as exc:
            return self._result(
                available=True,
                command=None,
                exit_code=None,
                stdout=None,
                stderr=None,
                duration_ms=0.0,
                started_at=started_at,
                findings_count=0,
                error=f"failed to build command: {exc}",
                raw_output_parsed=False,
            )

        command_str = " ".join(shlex.quote(part) for part in argv)
        loop_start = asyncio.get_event_loop().time()

        try:
            process = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    process.communicate(), timeout=timeout_seconds
                )
                exit_code = process.returncode
            except TimeoutError:
                process.kill()
                await process.wait()
                duration_ms = (asyncio.get_event_loop().time() - loop_start) * 1000
                return self._result(
                    available=True,
                    command=command_str,
                    exit_code=None,
                    stdout=None,
                    stderr=None,
                    duration_ms=duration_ms,
                    started_at=started_at,
                    findings_count=0,
                    error=f"tool timed out after {timeout_seconds}s",
                    raw_output_parsed=False,
                )
        except FileNotFoundError as exc:
            duration_ms = (asyncio.get_event_loop().time() - loop_start) * 1000
            return self._result(
                available=False,
                command=command_str,
                exit_code=None,
                stdout=None,
                stderr=None,
                duration_ms=duration_ms,
                started_at=started_at,
                findings_count=0,
                error=f"tool not installed: {exc}",
                raw_output_parsed=False,
            )
        except Exception as exc:
            duration_ms = (asyncio.get_event_loop().time() - loop_start) * 1000
            return self._result(
                available=True,
                command=command_str,
                exit_code=None,
                stdout=None,
                stderr=None,
                duration_ms=duration_ms,
                started_at=started_at,
                findings_count=0,
                error=f"tool execution failed: {exc}",
                raw_output_parsed=False,
            )

        duration_ms = (asyncio.get_event_loop().time() - loop_start) * 1000
        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")

        try:
            findings, raw_metadata = self.adapter.parse_output(stdout, stderr, exit_code or 0)
            parsed_ok = True
        except Exception as exc:
            findings, raw_metadata = [], {"parse_error": str(exc)}
            parsed_ok = False

        return self._result(
            available=True,
            command=command_str,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_ms=duration_ms,
            started_at=started_at,
            findings_count=len(findings),
            error=None,
            raw_output_parsed=parsed_ok,
            findings=findings,
            raw_metadata=raw_metadata,
        )

    def _result(
        self,
        *,
        available: bool,
        command: str | None,
        exit_code: int | None,
        stdout: str | None,
        stderr: str | None,
        duration_ms: float,
        started_at: datetime,
        findings_count: int,
        error: str | None,
        raw_output_parsed: bool,
        findings: list[dict[str, Any]] | None = None,
        raw_metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {
            "tool_name": self.adapter.name,
            "category": self.adapter.category,
            "available": available,
            "command": command,
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "duration_ms": duration_ms,
            "started_at": started_at,
            "findings_count": findings_count,
            "error": error,
            "raw_output_parsed": raw_output_parsed,
            "findings": findings or [],
            "raw_metadata": raw_metadata or {},
        }


async def run_all(
    adapters: list[ToolAdapter], target_path: str, config: dict[str, Any]
) -> list[dict[str, Any]]:
    runners = [ToolRunner(adapter) for adapter in adapters]
    return await asyncio.gather(*(runner.run(target_path, config) for runner in runners))
