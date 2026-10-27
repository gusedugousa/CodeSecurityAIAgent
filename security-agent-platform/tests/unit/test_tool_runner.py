import pytest

from app.tools.base import ToolAdapter
from app.tools.runner import ToolRunner


class _FakeUnavailableAdapter(ToolAdapter):
    name = "definitely-not-a-real-tool-xyz"
    category = "sast"

    def build_command(self, target_path, config):
        return [self.name, target_path]

    def parse_output(self, stdout, stderr, exit_code):
        return [], {}


class _EchoAdapter(ToolAdapter):
    name = "echo"
    category = "sast"

    def build_command(self, target_path, config):
        return ["echo", "hello"]

    def parse_output(self, stdout, stderr, exit_code):
        if "hello" in stdout:
            return [{"title": "echoed", "source_tool": self.name}], {}
        return [], {}


@pytest.mark.asyncio
async def test_runner_marks_unavailable_tool_without_raising():
    runner = ToolRunner(_FakeUnavailableAdapter())
    result = await runner.run("/tmp", {"tools": {}, "defaults": {"timeout_seconds": 5}})
    assert result["available"] is False
    assert result["error"] == "tool not installed"
    assert result["findings"] == []


@pytest.mark.asyncio
async def test_runner_executes_available_tool_and_parses_output():
    runner = ToolRunner(_EchoAdapter())
    result = await runner.run("/tmp", {"tools": {}, "defaults": {"timeout_seconds": 5}})
    assert result["available"] is True
    assert result["exit_code"] == 0
    assert result["findings_count"] == 1
    assert result["findings"][0]["title"] == "echoed"


@pytest.mark.asyncio
async def test_runner_handles_tool_timeout():
    class _SleepAdapter(ToolAdapter):
        name = "sleep"
        category = "sast"

        def build_command(self, target_path, config):
            return ["sleep", "5"]

        def parse_output(self, stdout, stderr, exit_code):
            return [], {}

    runner = ToolRunner(_SleepAdapter())
    result = await runner.run("/tmp", {"tools": {}, "defaults": {"timeout_seconds": 0.2}})
    assert result["available"] is True
    assert "timed out" in result["error"]
