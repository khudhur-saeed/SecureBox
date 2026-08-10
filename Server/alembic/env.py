import asyncio
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.ext.asyncio import async_engine_from_config
from alembic import context

# ---------------------------------------------------------------------
# 1. IMPORTS FOR SECUREBOX MODELS & SETTINGS
# ---------------------------------------------------------------------
from app.core.config import settings
from app.db.base import Base
import app.db.models  # Crucial: Register User, AuthChallenge & VaultItem in Base.metadata

# Alembic Config object to access .ini values
config = context.config

# Setup Python loggers
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Point target_metadata to our central Base class
target_metadata = Base.metadata

# Dynamically override the database URL from settings (.env file)
config.set_main_option("sqlalchemy.url", str(settings.DATABASE_URL))


# ---------------------------------------------------------------------
# 2. OFFLINE MIGRATIONS (Generates raw SQL statements without DB connection)
# ---------------------------------------------------------------------
def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,             # Detects changes in column data types (e.g., String lengths)
        compare_server_default=True,   # Detects default value changes
    )

    with context.begin_transaction():
        context.run_migrations()


# ---------------------------------------------------------------------
# 3. ONLINE ASYNC MIGRATIONS (Connects directly to PostgreSQL via asyncpg)
# ---------------------------------------------------------------------
def do_run_migrations(connection):
    """Callback function executed inside the async runner."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Creates an AsyncEngine and runs migrations using the event loop."""
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,  # NullPool ensures connections close immediately after migration
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    asyncio.run(run_async_migrations())


# ---------------------------------------------------------------------
# 4. EXECUTION SWITCH
# ---------------------------------------------------------------------
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()