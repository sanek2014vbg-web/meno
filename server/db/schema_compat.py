"""Диалект-безопасный lightweight-upgrade схемы Этапа 7.3 (реакции/ответы).

Прод на PostgreSQL мигрируется Alembic (b6c7d8e9f0a1). Но self-hosted
инсталляции на SQLite и тестовые БД, созданные до Этапа 7.3, обновляются
через init_db() -> create_all, который НЕ добавляет новые колонки в
существующие таблицы. Без этого модуля такой сервер падал бы с
'no such column: reactions_summary'.

Логика идемпотентна и проверяется через Inspector: каждый шаг выполняется
только если артефакта ещё нет. Работает на обоих диалектах одной SQL-грамматикой
(DEFAULT '{}' и NULL не требуют диалектных веток; backfill UPDATE — тоже).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import sqlalchemy as sa

if TYPE_CHECKING:  # pragma: no cover - только подсказки типов
    from sqlalchemy.engine import Connection

log = logging.getLogger("meno.db.schema_compat")


def _has_table(insp: sa.Inspector, name: str) -> bool:
    return name in insp.get_table_names()


def _has_column(insp: sa.Inspector, table: str, column: str) -> bool:
    return any(c["name"] == column for c in insp.get_columns(table))


def _has_index(insp: sa.Inspector, table: str, index: str) -> bool:
    return any(i["name"] == index for i in insp.get_indexes(table))


def ensure_reactions_schema(conn: "Connection") -> None:
    """Приводит существующую БД к схеме Этапа 7.3 (идемпотентно).

    Шаги:
    1. messages.reactions_summary TEXT NOT NULL DEFAULT '{}' + backfill '{}';
    2. messages.reply_to_id INTEGER + FK SET NULL + индекс idx_messages_reply_to;
    3. таблица reactions (CREATE TABLE IF NOT EXISTS безопасна и на SQLite,
       и на PG >= 9.x) с UNIQUE(message_id, user_id) и индексом по message_id.
    """
    insp = sa.inspect(conn)
    if not _has_table(insp, "messages"):
        return  # пустая БД: всё создаст create_all/Alembic целиком

    # 1. Денормализованная сводка реакций.
    if not _has_column(insp, "messages", "reactions_summary"):
        conn.execute(
            sa.text(
                "ALTER TABLE messages ADD COLUMN reactions_summary TEXT NOT NULL DEFAULT '{}'"
            )
        )
        log.info("schema_compat: added messages.reactions_summary")

    # 2. Ответы (reply-to). SQLite НЕ умеет добавлять FOREIGN KEY через
    # ALTER TABLE (только при CREATE TABLE), поэтому ограничение FK навешиваем
    # только на PostgreSQL. На SQLite каскады гарантирует уровень приложения:
    # DELETE-роуты чистят reply_to_id ссылочных сообщений вручную
    # (см. routes_messages._cascade_delete_message), а 'PRAGMA foreign_keys'
    # в тестовом conftest включён для новосозданных БД.
    if not _has_column(insp, "messages", "reply_to_id"):
        conn.execute(sa.text("ALTER TABLE messages ADD COLUMN reply_to_id INTEGER"))
        if conn.dialect.name == "postgresql":
            conn.execute(
                sa.text(
                    "ALTER TABLE messages ADD CONSTRAINT fk_messages_reply_to "
                    "FOREIGN KEY (reply_to_id) REFERENCES messages(id) ON DELETE SET NULL"
                )
            )
        log.info("schema_compat: added messages.reply_to_id")
    if not _has_index(insp, "messages", "idx_messages_reply_to"):
        conn.execute(
            sa.text("CREATE INDEX idx_messages_reply_to ON messages (reply_to_id)")
        )

    # 3. Таблица реакций (E2EE-blob, без знания эмодзи сервером).
    # 'INTEGER PRIMARY KEY' универсален: в SQLite это alias rowid и он
    # автоматически автоинкрементится; 'AUTOINCREMENT' — синтаксис только
    # SQLite и PG его отвергает. CREATE TABLE IF NOT EXISTS легален на обоих.
    if not _has_table(insp, "reactions"):
        conn.execute(
            sa.text(
                """
            CREATE TABLE IF NOT EXISTS reactions (
                id              INTEGER PRIMARY KEY,
                message_id      INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
                user_id         INTEGER NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
                encrypted_payload TEXT NOT NULL,
                created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
                CONSTRAINT uq_reactions_message_user UNIQUE (message_id, user_id)
            )
            """
            )
        )
        conn.execute(
            sa.text(
                "CREATE INDEX IF NOT EXISTS idx_reactions_message ON reactions (message_id)"
            )
        )
        log.info("schema_compat: created table reactions")
