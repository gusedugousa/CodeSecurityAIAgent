"""Checkpointing-ready scaffold for the analysis graph.

Future direction: a Postgres-backed LangGraph checkpointer for durable, resumable
analysis runs, keyed by analysis_id as the LangGraph thread_id.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from app.core.config import Settings


def get_checkpointer(settings: "Settings") -> Any | None:
    # Kept conservative for the MVP: we don't guess at which checkpointer classes are
    # importable in the pinned langgraph>=0.1.5 release, so no checkpointing is enabled
    # by default. Return a real checkpointer instance here (e.g. MemorySaver, or a future
    # Postgres-backed one) once verified against the installed langgraph version, and pass
    # it to app.orchestration.graph.build_graph(checkpointer=...).
    return None
