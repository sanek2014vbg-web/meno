from logging.config import fileConfig

import asyncio
import sys
import os
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import create_async_engine

from alembic import context

# Добавляем корень проекта в путь, чтобы импортировать серверные модули
sys.path.append(os.getcwd())

from server.database import Base
from server.config import DATABASE_URL

# Alembic Config object
config = context.config

# Настройка логирования
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Метаданные моделей для автогенерации миграций
target_metadata = Base.metadata

def run_migrations_offline() -> None:
    """Запуск миграций в offline режиме.

    URL берётся из DATABASE_URL (тот же источник, что и у online-режима):
    значение по умолчанию в alembic.ini — плейсхолдер driver://user:pass,
    который ломал --sql генерацию (NoSuchModuleError: sqlalchemy.dialects:driver).
    """
    url = DATABASE_URL
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()

async def run_migrations_online() -> None:
    """Запуск миграций в online режиме через asyncpg."""
    # Переопределяем URL из .ini файла на наш конфиг
    connectable = create_async_engine(
        DATABASE_URL,
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()

def do_run_migrations(connection):
    context.configure(
        connection=connection, 
        target_metadata=target_metadata,
        # Важно для PostgreSQL: используем именованные параметры
        dialect_opts={"paramstyle": "named"}
    )

    with context.begin_transaction():
        context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    # Запуск асинхронного цикла для онлайн-миграций
    asyncio.run(run_migrations_online())
