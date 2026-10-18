"""Connection layer MeNo: движок SQLAlchemy, пул соединений, фабрика сессий.

Атомарный модуль (рефакторинг god-module `database.py`). Отвечает строго за
физическое подключение к СУБД; схемы моделей — в `models_base.py`, логика
сессий/клинера — в `session_manager.py`.

Диалекты:
- PostgreSQL (asyncpg) — прод; пул настраивается через env;
- SQLite (aiosqlite)  — self-hosted lite / тесты; PRAGMA-инициализация
  (WAL + busy_timeout) гасит гонки блокировок при конкурентном доступе.
"""

import logging
from typing import Any, Dict

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from server.config import DATABASE_URL, IS_SQLITE
from server.db.models_base import Base  # noqa: F401  (переэкспорт для удобства:
# `from server.db.connection import Base` должен работать без доп. импортов)

logger = logging.getLogger("meno.db.connection")


def _engine_kwargs() -> Dict[str, Any]:
    kwargs: Dict[str, Any] = {"echo": False, "future": True}
    if not IS_SQLITE:
        # Пул PG настраивается окружением: минимум железа фиксируется RUNBOOK,
        # вертикальный рост VPS не требует правки кода.
        import os

        pool_size = int(os.environ.get("MENO_DB_POOL_SIZE", "8"))
        max_overflow = int(os.environ.get("MENO_DB_MAX_OVERFLOW", "2"))
        kwargs.update(
            pool_size=pool_size,
            max_overflow=max_overflow,
            pool_pre_ping=True,  # отбрасывает разорванные коннекты после рестарта PG
            pool_recycle=1800,  # короче typical idle timeout pgbouncer/pg
        )
    return kwargs


engine = create_async_engine(DATABASE_URL, **_engine_kwargs())

AsyncSessionLocal = async_sessionmaker(
    bind=engine, class_=AsyncSession, expire_on_commit=False
)


if IS_SQLITE:

    @event.listens_for(engine.sync_engine, "connect")
    def _sqlite_pragmas(
        dbapi_conn, _conn_record
    ):  # pragma: no cover - инфраструктурный хук
        """PRAGMA для SQLite: WAL снимает writer↔reader блокировки,
        busy_timeout превращает мгновенные 'database is locked' в ожидание.
        Дефект-фикс №1 (гонки блокировок в тестах).

        Плюс регистрация UTF-8 совместимой функции LOWER: встроенный LOWER()
        в SQLite знает только ASCII, из-за чего кириллический поиск
        ('Привет' != 'привет') молча ломался. Переопределяем lower через
        create_function(str.lower) — он корректно работает с Unicode."""
        cur = dbapi_conn.cursor()
        try:
            cur.execute("PRAGMA journal_mode=WAL;")
            cur.execute("PRAGMA busy_timeout=30000;")
            cur.execute("PRAGMA foreign_keys=ON;")
            cur.execute("PRAGMA synchronous=NORMAL;")
        finally:
            cur.close()
        # det=True: строки приходят как Python str (utf-8), а не bytes.
        dbapi_conn.create_function(
            "lower", 1, lambda s: s.lower() if s else s, deterministic=True
        )

else:

    @event.listens_for(engine.sync_engine, "connect")
    def _pg_session_settings(dbapi_conn, _conn_record):  # pragma: no cover
        """Однородное поведение таймаутов/кодировки во всех сессиях PG."""
        cur = dbapi_conn.cursor()
        try:
            cur.execute(text("SET statement_timeout = '30s'").text)
            cur.execute("SET timezone = 'UTC'")
            dbapi_conn.commit()
        finally:
            cur.close()


async def close_pool() -> None:
    """Закрывает пул соединений (вызывается из lifespan FastAPI)."""
    await engine.dispose()
