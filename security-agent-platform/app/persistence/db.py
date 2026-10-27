"""Async SQLAlchemy engine/session management.

Provides a lazily-constructed, module-cached engine/session-factory pair (mirroring the
lru_cache pattern in app.core.config) so callers elsewhere don't need to wire DI themselves.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import Settings, get_settings
from app.persistence.models import Base


def create_engine_from_settings(settings: Settings) -> AsyncEngine:
    return create_async_engine(settings.database_url)


def _sqlite_file_path(database_url: str) -> str | None:
    if not database_url.startswith("sqlite"):
        return None
    parsed = urlparse(database_url)
    path = parsed.path
    if not path:
        return None
    return path.lstrip("/") if not path.startswith("//") else path[1:]


async def init_db(engine: AsyncEngine) -> None:
    # SQLite needs its parent directory to exist before the file can be created;
    # Postgres has no equivalent filesystem dependency.
    sqlite_path = _sqlite_file_path(str(engine.url))
    if sqlite_path:
        parent = os.path.dirname(sqlite_path)
        if parent:
            os.makedirs(parent, exist_ok=True)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


def get_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        _engine = create_engine_from_settings(get_settings())
    return _engine


def get_session_factory_singleton() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        _session_factory = get_session_factory(get_engine())
    return _session_factory


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    session_factory = get_session_factory_singleton()
    async with session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
