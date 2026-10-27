"""Future work: STRIDE-style automated threat modeling from findings + architecture."""

from __future__ import annotations

from typing import Any

from app.agents.base import BaseAgent


class ThreatModelingAgent(BaseAgent):
    name = "threat_modeling"

    async def run(self, state: dict[str, Any]) -> dict[str, Any]:
        return state
