"""Text/data splitting utilities to keep LLM prompt sizes bounded.

Plain, independently callable functions - no chains, no state.
"""

from __future__ import annotations

from langchain_text_splitters import RecursiveCharacterTextSplitter


def split_code_for_context(code: str, chunk_size: int = 2000, chunk_overlap: int = 200) -> list[str]:
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        separators=["\n\n", "\n", " ", ""],
    )
    return splitter.split_text(code)


def split_findings_batch(items: list[dict], batch_size: int = 20) -> list[list[dict]]:
    if batch_size <= 0:
        raise ValueError("batch_size must be positive")
    return [items[i : i + batch_size] for i in range(0, len(items), batch_size)]
