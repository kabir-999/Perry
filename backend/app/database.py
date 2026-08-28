"""
SQLAlchemy engine/session setup.
"""
from collections.abc import AsyncGenerator
from urllib.parse import urlsplit

from sqlalchemy import event
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


_async_url = _to_async_url(settings.DATABASE_URL)


def iam_auth_engine_kwargs() -> dict:
    """Extra create_async_engine kwargs needed for IAM-authenticated Aurora
    connections — pool_recycle and connect_args. Empty when IAM auth is off.

    Used by both this module's own engine and Alembic's independent one
    (alembic/env.py builds its own engine from the same DATABASE_URL rather
    than importing this module's — migrations would otherwise try to
    connect with no password at all and fail the same way).
    """
    if not settings.DATABASE_IAM_AUTH:
        return {}
    return {
        # IAM auth tokens expire after 15 minutes; recycling well before
        # that guarantees a pooled connection is never reused with a stale
        # token.
        "pool_recycle": 600,
        # Express-configuration Aurora clusters (the AWS Free Tier path —
        # no VPC, no static password) only accept IAM-authenticated
        # connections over TLS. `ssl=True` uses the system's default trust
        # store, which already carries the AWS root CA the internet access
        # gateway presents (no RDS-specific CA bundle needed, unlike
        # classic VPC-attached RDS).
        "connect_args": {"ssl": True},
    }


def attach_iam_auth(async_engine, url: str) -> None:
    """Wire up automatic IAM auth-token generation on every new physical
    connection this engine opens. No-op when IAM auth is off."""
    if not settings.DATABASE_IAM_AUTH:
        return
    import boto3

    parts = urlsplit(url)
    rds_client = boto3.client("rds", region_name=settings.AWS_REGION)

    def _generate_iam_token() -> str:
        return rds_client.generate_db_auth_token(
            DBHostname=parts.hostname,
            Port=parts.port or 5432,
            DBUsername=parts.username,
        )

    @event.listens_for(async_engine.sync_engine, "do_connect")
    def _inject_iam_token(dialect, conn_rec, cargs, cparams):
        cparams["password"] = _generate_iam_token()


engine = create_async_engine(
    _async_url,
    echo=settings.DEBUG,
    pool_pre_ping=True,
    # SQLAlchemy's async default (5 + 10 overflow = up to 15 connections)
    # is sized for a much bigger instance than this app runs on. Each open
    # connection costs real memory on both this process and Postgres; this
    # app's actual concurrency (one scan's DB writes, a handful of API
    # requests) never needs anywhere near 15 at once.
    pool_size=3,
    max_overflow=2,
    **iam_auth_engine_kwargs(),
)
attach_iam_auth(engine, _async_url)

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
