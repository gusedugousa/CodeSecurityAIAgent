"""Future work: build a code knowledge graph / call graph for deeper SAST context."""

from __future__ import annotations

from typing import Any

from app.agents.base import BaseAgent


class CodeUnderstandingAgent(BaseAgent):
    name = "code_understanding"

    async def run(self, state: dict[str, Any]) -> dict[str, Any]:
        return state
