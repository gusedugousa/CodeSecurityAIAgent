"""Repository ingestion via GitPython: clone remote repos or pass through local paths."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from git import Repo
from git.exc import GitError

from app.core.errors import RepositoryIngestionError

_LANGUAGE_EXTENSIONS: dict[str, str] = {
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".jsx": "JavaScript",
    ".java": "Java",
    ".go": "Go",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".cpp": "C++",
    ".c": "C",
    ".rs": "Rust",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".tf": "Terraform",
    ".sh": "Shell",
    ".sql": "SQL",
}

_IGNORED_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".mypy_cache"}


class GitRepositoryIngestor:
    def __init__(self, workspace_dir: str) -> None:
        self.workspace_dir = Path(workspace_dir)

    def ingest(
        self,
        repo_url: str | None,
        branch: str,
        local_path: str | None,
        analysis_id: str,
    ) -> dict[str, Any]:
        if local_path:
            return self._ingest_local(local_path, branch)
        if repo_url:
            return self._ingest_remote(repo_url, branch, analysis_id)
        raise RepositoryIngestionError("either repo_url or local_path must be provided")

    def _ingest_remote(self, repo_url: str, branch: str, analysis_id: str) -> dict[str, Any]:
        destination = self.workspace_dir / analysis_id
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            # Shallow clone: MVP only needs the working tree at HEAD of the branch,
            # not full history, to keep ingestion fast and disk-light.
            repo = Repo.clone_from(repo_url, destination, branch=branch, depth=1)
        except GitError as exc:
            raise RepositoryIngestionError(
                f"failed to clone repository: {exc}", repo_url=repo_url
            ) from exc

        commit_sha = repo.head.commit.hexsha
        return self._build_metadata(
            repo_url=repo_url,
            branch=branch,
            commit_sha=commit_sha,
            local_path=str(destination),
        )

    def _ingest_local(self, local_path: str, branch: str) -> dict[str, Any]:
        path = Path(local_path)
        if not path.is_dir():
            raise RepositoryIngestionError(
                f"local_path does not exist or is not a directory: {local_path}",
                local_path=local_path,
            )

        commit_sha = None
        try:
            repo = Repo(path)
            commit_sha = repo.head.commit.hexsha
        except GitError:
            commit_sha = None

        return self._build_metadata(
            repo_url=None,
            branch=branch,
            commit_sha=commit_sha,
            local_path=str(path),
        )

    def _build_metadata(
        self,
        repo_url: str | None,
        branch: str | None,
        commit_sha: str | None,
        local_path: str,
    ) -> dict[str, Any]:
        file_count = 0
        total_size_bytes = 0
        language_counts: dict[str, int] = {}

        for root, dirs, files in os.walk(local_path):
            dirs[:] = [d for d in dirs if d not in _IGNORED_DIRS]
            for filename in files:
                file_count += 1
                file_path = Path(root) / filename
                try:
                    total_size_bytes += file_path.stat().st_size
                except OSError:
                    pass
                language = _LANGUAGE_EXTENSIONS.get(file_path.suffix.lower())
                if language:
                    language_counts[language] = language_counts.get(language, 0) + 1

        primary_languages = [
            lang for lang, _ in sorted(language_counts.items(), key=lambda kv: kv[1], reverse=True)
        ]

        return {
            "repo_url": repo_url,
            "branch": branch,
            "commit_sha": commit_sha,
            "local_path": local_path,
            "file_count": file_count,
            "total_size_bytes": total_size_bytes,
            "primary_languages": primary_languages,
            "cloned_at": datetime.now(UTC),
        }
