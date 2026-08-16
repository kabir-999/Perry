"""
SQLAlchemy engine/session setup.
"""
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.config import settings


def _to_async_url(url: str) -> str:
    """Ensure the DATABASE_URL uses an async driver (asyncpg)."""
    if url.startswith("postgresql+asyncpg://"):
        return url
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return url


engine = create_async_engine(
    _to_async_url(settings.DATABASE_URL),
    echo=settings.DEBUG,
    pool_pre_ping=True,
    # SQLAlchemy's async default (5 + 10 overflow = up to 15 connections)
    # is sized for a much bigger instance than this app runs on. Each open
    # connection costs real memory on both this process and Postgres; this
    # app's actual concurrency (one scan's DB writes, a handful of API
    # requests) never needs anywhere near 15 at once.
    pool_size=3,
    max_overflow=2,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    expire_on_commit=False,
    class_=AsyncSession,
)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session
