"""Архитектурный аудит Пункт 5: реестр TTL-джоб janitor_jobs + таблица chat_invites.

Создаёт две таблицы, связанные с фоновым дворником (server/services/janitor.py):

1. ``janitor_jobs`` — реестр регламентов очистки (message PK job + составной
   индекс (enabled, status) для due-скана). Каждая строка описывает одну
   TTL-джобу: table_name/ttl_column/grace_seconds/interval_seconds + поля
   advisory-лока (status/owner) и телеметрии (last_run_at/last_deleted_count).
   Новые таблицы с TTL подключаются к дворнику РЕГИСТРАЦИЕЙ СТРОКИ здесь или
   через ttl_registry.ensure_registered — без правки цикла дворника.

2. ``chat_invites`` — каркас-пример «новой таблицы с TTL»: одноразовые
   инваит-коды чатов с обязательным expires_at; вычищаются джобой
   'chat_invites_ttl' (регистрируется админ-командой/следующей миграцией).

Идемпотентность: существование таблиц/индексов проверяется через inspector —
повторный запуск или применение к БД, созданной из ORM-моделей
(init_db/Base.metadata.create_all), не падает.

down_revision = a1f2e3d4b5c6 (единый head графа на момент написания) —
новых heads не появляется; линейная история сохраняется.

Типы колонок строго соответствуют server/db/models_base.py (JanitorJob,
ChatInvite), чтобы autogenerate после применения не показывал diff.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b7c8d9e0f1a2"
down_revision: Union[str, Sequence[str], None] = "a1f2e3d4b5c6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_table(inspector, name: str) -> bool:
    return name in inspector.get_table_names()


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not _has_table(inspector, "janitor_jobs"):
        op.create_table(
            "janitor_jobs",
            sa.Column("job", sa.String(length=64), primary_key=True),
            sa.Column("table_name", sa.String(length=64), nullable=False),
            sa.Column(
                "ttl_column",
                sa.String(length=64),
                nullable=False,
                server_default="expires_at",
            ),
            sa.Column(
                "grace_seconds", sa.Integer(), nullable=False, server_default="0"
            ),
            sa.Column(
                "interval_seconds", sa.Integer(), nullable=False, server_default="60"
            ),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default="1"),
            sa.Column(
                "status", sa.String(length=16), nullable=False, server_default="idle"
            ),
            sa.Column("owner", sa.String(length=64), nullable=True),
            sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column(
                "last_deleted_count", sa.Integer(), nullable=False, server_default="0"
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
        )
        op.create_index(
            "idx_janitor_jobs_enabled_status",
            "janitor_jobs",
            ["enabled", "status"],
            unique=False,
        )

    inspector = sa.inspect(bind)
    if not _has_table(inspector, "chat_invites"):
        op.create_table(
            "chat_invites",
            sa.Column("id", sa.Integer(), autoincrement=True, primary_key=True),
            sa.Column("chat_id", sa.Integer(), nullable=False),
            sa.Column("code", sa.String(length=64), nullable=False),
            sa.Column("created_by", sa.Integer(), nullable=False),
            sa.Column(
                "max_uses", sa.Integer(), nullable=False, server_default="1"
            ),
            sa.Column("uses", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column(
                "created_at",
                sa.DateTime(),
                nullable=True,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.ForeignKeyConstraint(["chat_id"], ["chats.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="CASCADE"),
            sa.UniqueConstraint("code", name="uq_chat_invites_code"),
        )
        op.create_index(
            "idx_chat_invites_expires_at", "chat_invites", ["expires_at"], unique=False
        )
        op.create_index(
            "idx_chat_invites_chat", "chat_invites", ["chat_id"], unique=False
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if _has_table(inspector, "chat_invites"):
        # Индексы удаляем явно — на части движков drop_table это делает сам,
        # но явный вызов идемпотентен и переносим.
        existing_idx = {i["name"] for i in inspector.get_indexes("chat_invites")}
        if "idx_chat_invites_chat" in existing_idx:
            op.drop_index("idx_chat_invites_chat", table_name="chat_invites")
        if "idx_chat_invites_expires_at" in existing_idx:
            op.drop_index("idx_chat_invites_expires_at", table_name="chat_invites")
        op.drop_table("chat_invites")

    inspector = sa.inspect(bind)
    if _has_table(inspector, "janitor_jobs"):
        existing_idx = {i["name"] for i in inspector.get_indexes("janitor_jobs")}
        if "idx_janitor_jobs_enabled_status" in existing_idx:
            op.drop_index(
                "idx_janitor_jobs_enabled_status", table_name="janitor_jobs"
            )
        op.drop_table("janitor_jobs")
