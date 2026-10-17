"""v2.0 Пункт 2: сгорающие сообщения — колонка messages.expires_at + индекс.

Добавляет в таблицу messages абсолютный момент физической смерти сообщения
(tz-aware UTC) и диапазонный индекс для janitor'а. Колонка опциональна:
NULL означает «сообщение не сгорает», поэтому миграция полностью безопасна
для существующих данных и выполняется без backfill.

Идемпотентность: существование колонки/индекса проверяется через inspector —
повторный запуск (или применение к БД, созданной из ORM-моделей) не падает.

down_revision = f7a8b9cafed0 (merge-revision Этапа 1.5) — миграция строго
следует за единым head графа, новых heads не появляется.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a1f2e3d4b5c6"
down_revision: Union[str, Sequence[str], None] = "f7a8b9cafed0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_column(inspector, table: str, column: str) -> bool:
    return any(c["name"] == column for c in inspector.get_columns(table))


def _has_index(inspector, table: str, index: str) -> bool:
    return any(i["name"] == index for i in inspector.get_indexes(table))


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "messages" not in inspector.get_table_names():
        return  # пустая БД: таблицы создаст более ранняя миграция
    if not _has_column(inspector, "messages", "expires_at"):
        op.add_column(
            "messages",
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        )
    inspector = sa.inspect(bind)
    if not _has_index(inspector, "messages", "idx_messages_expires_at"):
        op.create_index(
            "idx_messages_expires_at", "messages", ["expires_at"], unique=False
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "messages" not in inspector.get_table_names():
        return
    if _has_index(inspector, "messages", "idx_messages_expires_at"):
        op.drop_index("idx_messages_expires_at", table_name="messages")
    inspector = sa.inspect(bind)
    if _has_column(inspector, "messages", "expires_at"):
        op.drop_column("messages", "expires_at")
