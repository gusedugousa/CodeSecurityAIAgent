"""Object storage abstraction for evidence/reports/artifacts/logs.

MVP ships a real local-filesystem-backed implementation. Cloud targets (S3-compatible,
Azure Blob) are named extension points, stubbed until wired to real SDKs.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from pathlib import Path

from app.core.config import Settings


class ObjectStore(ABC):
    @abstractmethod
    async def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> str: ...

    @abstractmethod
    async def get(self, key: str) -> bytes: ...

    @abstractmethod
    async def exists(self, key: str) -> bool: ...

    @abstractmethod
    async def delete(self, key: str) -> None: ...


def _sanitize_key(key: str) -> str:
    if ".." in Path(key).parts:
        raise ValueError(f"invalid object key (path traversal rejected): {key!r}")
    return key


class LocalFilesystemObjectStore(ObjectStore):
    def __init__(self, root_dir: str) -> None:
        self._root_dir = Path(root_dir)
        self._root_dir.mkdir(parents=True, exist_ok=True)

    def _resolve(self, key: str) -> Path:
        return self._root_dir / _sanitize_key(key)

    async def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> str:
        path = self._resolve(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return f"file://{path.resolve()}"

    async def get(self, key: str) -> bytes:
        path = self._resolve(key)
        return path.read_bytes()

    async def exists(self, key: str) -> bool:
        return self._resolve(key).exists()

    async def delete(self, key: str) -> None:
        path = self._resolve(key)
        if path.exists():
            path.unlink()


class S3CompatibleObjectStorePlaceholder(ObjectStore):
    """TODO: wire real S3-compatible client — see docs/extension_points.md."""

    def __init__(self, bucket: str, endpoint_url: str | None = None) -> None:
        self._bucket = bucket
        self._endpoint_url = endpoint_url

    async def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> str:
        raise NotImplementedError("TODO: wire real Azure Blob / S3-compatible client — see docs/extension_points.md")

    async def get(self, key: str) -> bytes:
        raise NotImplementedError("TODO: wire real Azure Blob / S3-compatible client — see docs/extension_points.md")

    async def exists(self, key: str) -> bool:
        raise NotImplementedError("TODO: wire real Azure Blob / S3-compatible client — see docs/extension_points.md")

    async def delete(self, key: str) -> None:
        raise NotImplementedError("TODO: wire real Azure Blob / S3-compatible client — see docs/extension_points.md")


class AzureBlobObjectStorePlaceholder(ObjectStore):
    """TODO: wire real Azure Blob / S3-compatible client — see docs/extension_points.md."""

    def __init__(self, container: str, account_url: str | None = None) -> None:
        self._container = container
        self._account_url = account_url

    async def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> str:
        raise NotImplementedError("TODO: wire real Azure Blob / S3-compatible client — see docs/extension_points.md")

    async def get(self, key: str) -> bytes:
        raise NotImplementedError("TODO: wire real Azure Blob / S3-compatible client — see docs/extension_points.md")

    async def exists(self, key: str) -> bool:
        raise NotImplementedError("TODO: wire real Azure Blob / S3-compatible client — see docs/extension_points.md")

    async def delete(self, key: str) -> None:
        raise NotImplementedError("TODO: wire real Azure Blob / S3-compatible client — see docs/extension_points.md")


def get_object_store(settings: Settings) -> ObjectStore:
    root = os.path.join(settings.reports_dir, "..", "objects")
    return LocalFilesystemObjectStore(root_dir=root)
