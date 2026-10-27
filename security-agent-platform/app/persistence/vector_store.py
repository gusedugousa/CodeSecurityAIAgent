"""Vector DB abstraction for future RAG. pgvector/Qdrant/Azure AI Search are the named
future architecture targets and are stubbed until wired; the in-memory implementation
is real and usable for tests/demos today.
"""

from __future__ import annotations

import math
from abc import ABC, abstractmethod

from app.core.config import Settings


class VectorStore(ABC):
    @abstractmethod
    async def upsert(self, doc_id: str, text: str, embedding: list[float], metadata: dict) -> None: ...

    @abstractmethod
    async def query(self, embedding: list[float], top_k: int = 5) -> list[dict]: ...


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    mag_a = math.sqrt(sum(x * x for x in a))
    mag_b = math.sqrt(sum(y * y for y in b))
    if mag_a == 0.0 or mag_b == 0.0:
        return 0.0
    return dot / (mag_a * mag_b)


class InMemoryVectorStorePlaceholder(VectorStore):
    def __init__(self) -> None:
        self._store: dict[str, tuple[list[float], dict, str]] = {}

    async def upsert(self, doc_id: str, text: str, embedding: list[float], metadata: dict) -> None:
        self._store[doc_id] = (embedding, metadata, text)

    async def query(self, embedding: list[float], top_k: int = 5) -> list[dict]:
        scored = [
            {"doc_id": doc_id, "score": _cosine_similarity(embedding, stored_embedding), "metadata": metadata}
            for doc_id, (stored_embedding, metadata, _text) in self._store.items()
        ]
        scored.sort(key=lambda item: item["score"], reverse=True)
        return scored[:top_k]


class PgVectorStorePlaceholder(VectorStore):
    """TODO: wire pgvector — future RAG backend, see docs/extension_points.md."""

    def __init__(self, connection_url: str, table_name: str = "embeddings") -> None:
        self._connection_url = connection_url
        self._table_name = table_name

    async def upsert(self, doc_id: str, text: str, embedding: list[float], metadata: dict) -> None:
        raise NotImplementedError("TODO: wire pgvector — see docs/extension_points.md")

    async def query(self, embedding: list[float], top_k: int = 5) -> list[dict]:
        raise NotImplementedError("TODO: wire pgvector — see docs/extension_points.md")


class QdrantVectorStorePlaceholder(VectorStore):
    """TODO: wire Qdrant — future RAG backend, see docs/extension_points.md."""

    def __init__(self, url: str, collection_name: str = "findings") -> None:
        self._url = url
        self._collection_name = collection_name

    async def upsert(self, doc_id: str, text: str, embedding: list[float], metadata: dict) -> None:
        raise NotImplementedError("TODO: wire Qdrant — see docs/extension_points.md")

    async def query(self, embedding: list[float], top_k: int = 5) -> list[dict]:
        raise NotImplementedError("TODO: wire Qdrant — see docs/extension_points.md")


class AzureAISearchVectorStorePlaceholder(VectorStore):
    """TODO: wire Azure AI Search — future RAG backend, see docs/extension_points.md."""

    def __init__(self, endpoint: str, index_name: str, api_key: str | None = None) -> None:
        self._endpoint = endpoint
        self._index_name = index_name
        self._api_key = api_key

    async def upsert(self, doc_id: str, text: str, embedding: list[float], metadata: dict) -> None:
        raise NotImplementedError("TODO: wire Azure AI Search — see docs/extension_points.md")

    async def query(self, embedding: list[float], top_k: int = 5) -> list[dict]:
        raise NotImplementedError("TODO: wire Azure AI Search — see docs/extension_points.md")


def get_vector_store(settings: Settings) -> VectorStore:
    return InMemoryVectorStorePlaceholder()
