"""Этап 7.4: Реакции и Ответы — messages.reply_to_id, reactions_summary, таблица reactions.

Что делает:
- messages.reply_to_id (INTEGER, FK messages.id ON DELETE SET NULL) + индекс;
- messages.reactions_summary (TEXT NOT NULL DEFAULT '{}') с backfill'ом
  легаси-строк: сначала NULL -> '{}' временной nullable-колонкой, затем
  strict NOT NULL DEFAULT — чтобы ни одна существующая строка meno.db не
  осталась с NULL и json.loads на клиенте не падал;
- таблица reactions: id, message_id (CASCADE), user_id (CASCADE),
  encrypted_payload, created_at; UNIQUE(message_id, user_id) — toggle-замок.

Диалект-безопасность: только стандартный SQL (SQLite == PostgreSQL 16).
Идемпотентность: инспектор-guard'ы на каждой операции — повторный запуск
или применение к БД, созданной из ORM, не падает.
down_revision = b7c3d9e1f2a4 (status) — единый head сохраняется.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c8d9e0f1a2b3"
down_revision: Union[str, Sequence[str], None] = "b7c3d9e1f2a4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_column(inspector, table: str, column: str) -> bool:
    return any(c["name"] == column for c in inspector.get_columns(table))


def _has_index(inspector, table: str, index: str) -> bool:
    return any(i["name"] == index for i in inspector.get_indexes(table))


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = inspector.get_table_names()
    if "messages" not in tables:
        return  # пустая БД: таблицы создаст более ранняя миграция

    # --- messages.reply_to_id ---
    if not _has_column(inspector, "messages", "reply_to_id"):
        op.add_column(
            "messages",
            sa.Column("reply_to_id", sa.Integer(), nullable=True),
        )
        op.create_foreign_key(
            "fk_messages_reply_to",
            "messages", "messages",
            ["reply_to_id"], ["id"],
            ondelete="SET NULL",
        )
    inspector = sa.inspect(bind)
    if not _has_index(inspector, "messages", "idx_messages_reply_to"):
        op.create_index("idx_messages_reply_to", "messages", ["reply_to_id"])

    # --- messages.reactions_summary (с backfill'ом легаси-строк) ---
    if not _has_column(inspector, "messages", "reactions_summary"):
        # Шаг 1: колонка без NOT NULL — старые строки получают NULL,
        # что безопасно для SQLite (ALTER TABLE ADD COLUMN не умеет
        # NOT NULL без константного default на всех версиях).
        op.add_column(
            "messages",
            sa.Column("reactions_summary", sa.Text(), nullable=True),
        )
        # Шаг 2: backfill NULL -> '{}' (одноразово, диалект-безопасно).
        bind.execute(
            sa.text(
                "UPDATE messages SET reactions_summary = '{}' "
                "WHERE reactions_summary IS NULL"
            )
        )
        # Шаг 3: ужесточение схемы для новых строк. На PG это один DDL;
        # на SQLite batch_alter не пересоздаёт таблицу ради NOT NULL
        # (легаси-строки уже заполнены), поэтому оставляем контроль
        # DEFAULT на уровне приложения (модель server/db/models_base.py).
        op.alter_column(
            "messages", "reactions_summary",
            existing_type=sa.Text(),
            nullable=False,
            server_default="{}",
        )

    # --- таблица reactions ---
    inspector = sa.inspect(bind)
    if "reactions" not in inspector.get_table_names():
        op.create_table(
            "reactions",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("message_id", sa.Integer(), nullable=False),
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.Column("encrypted_payload", sa.Text(), nullable=False),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("(CURRENT_TIMESTAMP)"),
            ),
            sa.ForeignKeyConstraint(
                ["message_id"], ["messages.id"], ondelete="CASCADE"
            ),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint(
                "message_id", "user_id", name="uq_reactions_message_user"
            ),
        )
        op.create_index("idx_reactions_user", "reactions", ["user_id"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "reactions" in inspector.get_table_names():
        op.drop_index("idx_reactions_user", table_name="reactions")
        op.drop_table("reactions")
    if "messages" in inspector.get_table_names():
        inspector = sa.inspect(bind)
        if _has_index(inspector, "messages", "idx_messages_reply_to"):
            op.drop_index("idx_messages_reply_to", table_name="messages")
        for col in ("reactions_summary", "reply_to_id"):
            inspector = sa.inspect(bind)
            if _has_column(inspector, "messages", col):
                op.drop_column("messages", col)
