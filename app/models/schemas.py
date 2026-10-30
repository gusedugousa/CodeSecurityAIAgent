"""Model-layer request/response types used internally by the LiteLLM client."""

from __future__ import annotations

from pydantic import BaseModel

from app.api.schemas import ModelCallMetadata

__all__ = ["ModelCallMetadata", "ModelRequest", "ModelResponse"]


class ModelRequest(BaseModel):
    messages: list[dict[str, str]]
    role: str
    analysis_id: str
    max_tokens: int | None = None
    temperature: float = 0.2


class ModelResponse(BaseModel):
    content: str
    metadata: ModelCallMetadata
