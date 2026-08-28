import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool
from sqlalchemy.ext.asyncio import async_engine_from_config

from app.config import settings
from app.database import Base, attach_iam_auth, iam_auth_engine_kwargs

# Import models so they register on Base.metadata before autogenerate runs.
import app.models  # noqa: F401

# Async driver suffixes SQLAlchemy recognises. When the app's DATABASE_URL uses
# one of these (e.g. postgresql+asyncpg), migrations must run through an async
# engine + connection.run_sync(...); driving an async DBAPI from Alembic's
# plain sync engine raises "MissingGreenlet: greenlet_spawn has not been
# called". A bare `postgresql://` is coerced to the sync psycopg driver so it
# also works without pinning a driver in the URL.
_ASYNC_DRIVERS = ("+asyncpg", "+aiosqlite", "+asyncmy", "+aiomysql", "+psycopg_async")


def _normalize_url(url: str) -> str:
    if url.startswith("postgresql://"):
        # IAM-authenticated Aurora connections are wired up (attach_iam_auth)
        # for the asyncpg dialect specifically — forcing the async path here
        # too, rather than the default sync psycopg rewrite, keeps both
        # drivers from ever diverging on how the IAM token/SSL connect args
        # get applied.
        driver = "postgresql+asyncpg://" if settings.DATABASE_IAM_AUTH else "postgresql+psycopg://"
        return url.replace("postgresql://", driver, 1)
    return url


def _is_async(url: str) -> bool:
    return any(driver in url for driver in _ASYNC_DRIVERS)


config = context.config
config.set_main_option("sqlalchemy.url", _normalize_url(settings.DATABASE_URL))

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def _do_run_migrations(connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def _run_migrations_async() -> None:
    # Alembic builds its own engine straight from DATABASE_URL rather than
    # importing app.database's — without also wiring IAM auth here,
    # migrations against an express-configuration Aurora cluster would try
    # to connect with no password and fail exactly like the app would.
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        **iam_auth_engine_kwargs(),
    )
    attach_iam_auth(connectable, config.get_main_option("sqlalchemy.url"))
    async with connectable.connect() as connection:
        await connection.run_sync(_do_run_migrations)
    await connectable.dispose()


def _run_migrations_sync() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        _do_run_migrations(connection)


def run_migrations_online() -> None:
    if _is_async(config.get_main_option("sqlalchemy.url")):
        asyncio.run(_run_migrations_async())
    else:
        _run_migrations_sync()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
