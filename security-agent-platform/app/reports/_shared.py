"""Internal helpers shared across report generators. Not part of the public report contract."""

from __future__ import annotations

from typing import Any

SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


def as_dict(item: Any) -> dict:
    if item is None:
        return {}
    if isinstance(item, dict):
        return item
    model_dump = getattr(item, "model_dump", None)
    if callable(model_dump):
        try:
            return model_dump(mode="json")
        except TypeError:
            return model_dump()
    return dict(item)


def severity_sort_key(finding: dict) -> tuple:
    severity = finding.get("severity")
    return (SEVERITY_ORDER.get(severity, 99), finding.get("file_path") or "")
