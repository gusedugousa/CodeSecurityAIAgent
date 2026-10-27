"""Future work: dedicated cloud security posture scanning beyond Checkov's IaC checks (e.g. live cloud API scanning)."""

from __future__ import annotations

from typing import Any

from app.agents.base import BaseAgent


class IaCCloudSecurityAgent(BaseAgent):
    name = "iac_cloud_security"

    async def run(self, state: dict[str, Any]) -> dict[str, Any]:
        return state
