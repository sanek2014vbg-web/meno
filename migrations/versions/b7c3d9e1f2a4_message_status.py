"""Этап 7.3: Статусы сообщений — sent -> delivered -> read.

Добавляет в таблицу messages линейный статус (native_enum=False => VARCHAR
+ CHECK, одинаково на SQLite и PostgreSQL 16) и временные метки переходов
delivered_at / read_at (tz-aware UTC).

Безопасность данных:
- все колонки nullable на уровне DDL; server_default='sent' заполняет
  новые строки, а одноразовый backfill приводит легаси-строки (NULL) к
  'sent' — сравнение `status < :new` в PATCH-роуте тогда работает корректно;
- идемпотентность: существование колонок/индекса проверяется инспектором,
  повторный запуск или применение к БД, созданной из ORM, не падает.

down_revision = a1f2e3d4b5c6 (expires_at) — новых heads не появляется.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b7c3d9e1f2a4"
down_revision: Union[str, Sequence[str], None] = "a1f2e3d4b5c6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_STATUS_VALUES = ("sent", "delivered", "read")


def _has_column(inspector, table: str, column: str) -> bool:
    return any(c["name"] == column for c in inspector.get_columns(table))


def _has_index(inspector, table: str, index: str) -> bool:
    return any(i["name"] == index for i in inspector.get_indexes(table))


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "messages" not in inspector.get_table_names():
        return  # пустая БД: таблицы создаст более ранняя миграция

    if not _has_column(inspector, "messages", "status"):
        op.add_column(
            "messages",
            sa.Column(
                "status",
                sa.Enum(*_STATUS_VALUES, name="message_status",
                        native_enum=False, length=16),
                nullable=True,
                server_default="sent",
            ),
        )
    if not _has_column(inspector, "messages", "delivered_at"):
        op.add_column(
            "messages",
            sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        )
    if not _has_column(inspector, "messages", "read_at"):
        op.add_column(
            "messages",
            sa.Column("read_at", sa.DateTime(timezone=True), nullable=True),
        )

    # Одноразовый backfill легаси-строк (NULL -> 'sent'): диалект-безопасно.
    bind.execute(
        sa.text("UPDATE messages SET status = 'sent' WHERE status IS NULL")
    )

    inspector = sa.inspect(bind)
    if not _has_index(inspector, "messages", "idx_messages_chat_status"):
        op.create_index(
            "idx_messages_chat_status", "messages", ["chat_id", "status"]
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "messages" not in inspector.get_table_names():
        return
    if _has_index(inspector, "messages", "idx_messages_chat_status"):
        op.drop_index("idx_messages_chat_status", table_name="messages")
    for col in ("read_at", "delivered_at", "status"):
        inspector = sa.inspect(bind)
        if _has_column(inspector, "messages", col):
            op.drop_column("messages", col)
