"""Structured output parsing utilities for LLM responses.

Small, single-purpose functions - no chains, no orchestration. Callers invoke
these directly after getting raw text back from a model client.
"""

from __future__ import annotations

import json
import re
from typing import Literal

from langchain_core.output_parsers import PydanticOutputParser
from pydantic import BaseModel

_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL | re.IGNORECASE)


def parse_json_response(raw_text: str, fallback: dict | None = None) -> dict:
    if not raw_text or not raw_text.strip():
        return fallback if fallback is not None else {}

    try:
        parsed = json.loads(raw_text)
        if isinstance(parsed, dict):
            return parsed
    except (json.JSONDecodeError, TypeError):
        pass

    fence_match = _FENCE_RE.search(raw_text)
    if fence_match:
        try:
            parsed = json.loads(fence_match.group(1))
            if isinstance(parsed, dict):
                return parsed
        except (json.JSONDecodeError, TypeError):
            pass

    first_brace = raw_text.find("{")
    last_brace = raw_text.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        candidate = raw_text[first_brace : last_brace + 1]
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except (json.JSONDecodeError, TypeError):
            pass

    return fallback if fallback is not None else {}


def parse_remediation_response(raw_text: str, finding_id: str) -> dict:
    fallback = {
        "finding_id": finding_id,
        "summary": "Automated remediation parsing failed; raw model output preserved below.",
        "patch_diff": None,
        "explanation": raw_text or "",
        "generated_by_model": None,
    }
    parsed = parse_json_response(raw_text, fallback=None)
    if not parsed:
        return fallback

    return {
        "finding_id": finding_id,
        "summary": parsed.get("summary", fallback["summary"]),
        "patch_diff": parsed.get("patch_diff"),
        "explanation": parsed.get("explanation", raw_text or ""),
        "generated_by_model": None,
    }


class TriageResult(BaseModel):
    is_true_positive: bool
    confidence: Literal["high", "medium", "low"]
    rationale: str


def get_finding_triage_parser() -> PydanticOutputParser:
    return PydanticOutputParser(pydantic_object=TriageResult)
