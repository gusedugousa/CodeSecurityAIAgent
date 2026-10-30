"""Future work: dynamic validation/exploitability confirmation of static findings."""

from __future__ import annotations

from typing import Any

from app.agents.base import BaseAgent


class ValidationAgent(BaseAgent):
    name = "validation_exploitability"

    async def run(self, state: dict[str, Any]) -> dict[str, Any]:
        return state
