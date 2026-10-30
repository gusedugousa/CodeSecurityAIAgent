"""Clones/validates the target repository and seeds repository_metadata in state."""

from __future__ import annotations

from typing import Any

from app.agents.base import BaseAgent
from app.core.errors import RepositoryIngestionError
from app.tools.git import GitRepositoryIngestor


class RepoIngestionAgent(BaseAgent):
    name = "repo_ingestion"

    async def run(self, state: dict[str, Any]) -> dict[str, Any]:
        analysis_id = state.get("analysis_id", "unknown")
        workspace_dir = state.get("workspace_dir", "./data/workspaces")
        ingestor = GitRepositoryIngestor(workspace_dir)

        try:
            metadata = ingestor.ingest(
                repo_url=state.get("repo_url"),
                branch=state.get("branch", "main"),
                local_path=state.get("local_path"),
                analysis_id=analysis_id,
            )
        except RepositoryIngestionError as exc:
            # Fatal: with no repository there is nothing for any downstream agent to scan,
            # so we short-circuit the graph straight to the report node (see orchestration/graph.py).
            errors = [*state.get("errors", []), f"repository ingestion failed: {exc.message}"]
            return {**state, "errors": errors, "fatal_error": True}
        except Exception as exc:
            errors = [*state.get("errors", []), f"repository ingestion failed unexpectedly: {exc}"]
            return {**state, "errors": errors, "fatal_error": True}

        return {
            **state,
            "local_repo_path": metadata["local_path"],
            "repository_metadata": metadata,
            "commit_sha": metadata.get("commit_sha"),
        }
