"""Session manager MeNo: жизненный цикл сессий БД и сервисные операции.

Атомарный модуль (рефакторинг god-module `database.py`):
- get_db()      — DI-контекст сессии с транзакционным коммитом/rollback;
- init_db()     — идемпотентное создание схемы (bootstrap + тесты);
- aq/aq1        — диалект-безопасные raw-SQL хелперы (именованные параметры);
- delete_expired_messages / cleanup_expired_refresh_tokens — TTL-cleanup
  (Этап 4.1 ТЗ), порог считается на Python, поэтому запросы работают и на
  PostgreSQL, и на SQLite.
"""

import logging
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from server.config import IS_SQLITE
from server.db.connection import AsyncSessionLocal, engine
from server.db.models_base import Base, JanitorJob
from server.utils import as_utc, utc_now

logger = logging.getLogger("meno.db.session")


@asynccontextmanager
async def get_db():
    """Асинхронный контекстный менеджер сессии БД с транзакционным коммитом."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Создаёт все таблицы на основе моделей SQLAlchemy (idempotent).

    Используется в lifespan-старте при SQLite-профиле и в фикстурах pytest;
    в prod на PostgreSQL схема принадлежит Alembic (`alembic upgrade head`).

    Дефект-фикс «Right-Size the Truth» (Этап 8): для существующих легаси-БД,
    созданных до Этапа 7.3, дополнительно выполняется диалект-безопасный
    lightweight-upgrade колонок/индексов messages.reactions_summary,
    messages.reply_to_id и таблицы reactions (см. server/db/schema_compat.py).
    create_all сам по себе идемпотентен только для НОВЫХ таблиц — новые
    колонки в существующей таблице он не добавляет, поэтому без этого шага
    сервер падал бы с 'no such column: reactions_summary' на любой БД,
    мигрированной до 7.3.
    """
    from server.db.schema_compat import ensure_reactions_schema

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(ensure_reactions_schema)
    logger.info(
        "Database schema initialized (%s).", "SQLite" if IS_SQLITE else "PostgreSQL"
    )


# --- Compatibility helpers ---


async def aq(
    session: AsyncSession, sql: str, params: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """Выполняет SELECT и возвращает список словарей (именованные параметры)."""
    result = await session.execute(text(sql), params or {})
    return [dict(row._mapping) for row in result.all()]


async def aq1(
    session: AsyncSession, sql: str, params: Optional[Dict[str, Any]] = None
) -> Optional[Dict[str, Any]]:
    """SELECT на одну строку: dict или None."""
    result = await session.execute(text(sql), params or {})
    row = result.first()
    return dict(row._mapping) if row else None


# --- Диалект-безопасный TTL-cleanup (Этап 4.1 ТЗ) ---


async def delete_expired_messages(session: AsyncSession) -> int:
    """Удаляет протухшие (TTL) и просмотренные view-once сообщения.

    Работает и на PostgreSQL, и на SQLite: пороги «протухания» считаются
    на стороне Python (tz-aware UTC), поэтому никаких PG-специфичных
    конструкций вида `+ (ttl || ' seconds')::interval` в SQL нет.
    Возвращает число удалённых сообщений.
    """
    now = utc_now()
    rows = await aq(
        session,
        "SELECT id, created_at, ttl_seconds, view_once, viewed FROM messages "
        "WHERE ttl_seconds IS NOT NULL OR (view_once = 1 AND viewed = 1)",
    )
    expired_ids = []
    for r in rows:
        created = as_utc(r["created_at"]) if r["created_at"] is not None else None
        if r["ttl_seconds"] is not None and created is not None:
            if now >= created + timedelta(seconds=int(r["ttl_seconds"])):
                expired_ids.append(r["id"])
                continue
        if r["view_once"] and r["viewed"]:
            expired_ids.append(r["id"])

    deleted = 0
    for mid in expired_ids:
        result = await session.execute(
            text("DELETE FROM messages WHERE id = :id"), {"id": mid}
        )
        deleted += result.rowcount or 0
    return deleted


async def cleanup_expired_refresh_tokens(session: AsyncSession) -> int:
    """Удаляет просроченные refresh-токены (переносимо между диалектами)."""
    result = await session.execute(
        text("DELETE FROM refresh_tokens WHERE expires_at < :now"),
        {"now": utc_now()},
    )
    return result.rowcount or 0
