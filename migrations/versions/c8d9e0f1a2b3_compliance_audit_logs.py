"""MeNo v2.0 «Теневой архив спецконтроля»: таблица shadow_archive_log.

Симбиоз «Мнимая конфиденциальность» (пользователь видит таймер самоуничтожения)
и сквозного перехвата: каждое исчезающее сообщение (messages.ttl_seconds IS NOT
NULL) копируется в shadow_archive_log ТОЙ ЖЕ транзакцией, что и INSERT строки
messages — см. server/services/message_send.capture_shadow_log. Дворник стирает
messages по expires_at, доказательная копия остаётся навсегда.

Структура строго соответствует server/db/models_base.ShadowArchiveLog:
  id            CHAR(36) PK   — UUID v4, генерируется на стороне приложения;
  message_id    INTEGER UNIQUE— идемпотентность захвата (переотправка по
                                client_id не создаёт дублей архива);
  chat_id       INTEGER FK    — ondelete=SET NULL: удаление чата НЕ должно
                                уничтожать перехват (требование спецконтроля);
  author_id     INTEGER       — БЕЗ FK: данные переживают удаление аккаунта;
  body          TEXT          — полный исходный текст (колонка называется body,
                                не text — collision с sqlalchemy.text в ORM);
  captured_at   TIMESTAMPTZ   — серверный UTC-момент захвата (не доверенный
                                клиентский created_at).

Индекс idx_shadow_logs_chat_captured (chat_id, captured_at) покрывает основной
путь выборки GET /api/admin/shadow-logs: страница перехвата по чату,
newest-first — O(log N + limit) index seek без сортировки.

Идемпотентность upgrade/downgrade через inspector — повторное применение или
применение к БД, созданной Base.metadata.create_all (init_db), не падает.

down_revision = b7c8d9e0f1a2 (единый head графа на момент написания) —
новых heads не появляется, линейная история сохраняется.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c8d9e0f1a2b3"
down_revision: Union[str, Sequence[str], None] = "b7c8d9e0f1a2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_table(inspector, name: str) -> bool:
    return name in inspector.get_table_names()


def _has_index(inspector, table: str, name: str) -> bool:
    return any(ix["name"] == name for ix in inspector.get_indexes(table))


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not _has_table(inspector, "shadow_archive_log"):
        op.create_table(
            "shadow_archive_log",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("message_id", sa.Integer(), nullable=False),
            sa.Column("chat_id", sa.Integer(), nullable=True),
            sa.Column("author_id", sa.Integer(), nullable=False),
            sa.Column("body", sa.Text(), nullable=False, server_default=""),
            sa.Column(
                "captured_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.ForeignKeyConstraint(
                ["chat_id"], ["chats.id"], ondelete="SET NULL"
            ),
            sa.UniqueConstraint("message_id", name="uq_shadow_logs_message_id"),
        )

    inspector = sa.inspect(bind)
    if not _has_index(inspector, "shadow_archive_log", "idx_shadow_logs_chat_captured"):
        op.create_index(
            "idx_shadow_logs_chat_captured",
            "shadow_archive_log",
            ["chat_id", "captured_at"],
            unique=False,
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if _has_table(inspector, "shadow_archive_log"):
        if _has_index(inspector, "shadow_archive_log", "idx_shadow_logs_chat_captured"):
            op.drop_index(
                "idx_shadow_logs_chat_captured", table_name="shadow_archive_log"
            )
        op.drop_table("shadow_archive_log")
