"""Merge heads: единый линейный граф миграций MeNo (фикс A6/P0).

Конфликт веток в истории репозитория:

    80b0e94ce7e3 (initial)
        ├── 30b90143856c  (add refresh_tokens table)            <- legacy-ветка, head #1
        └── a1b2c3d4e5f6 -> c4d5e6f7a8b9 -> d5e6f7a8b9ca
                          -> e6f7a8b9cafe (fulltext russian)    <- v1.1-ветка, head #2

Ветка v1.1 предполагала, что таблица `refresh_tokens` уже существует (её
создаёт initial-миграция), но в легаси-БД она появлялась только из
30b90143856c — отсюда два расходящихся head и падение `alembic upgrade head`.

Смысловое слияние (поэтому down_revision — КОРТЕЖ из двух head'ов):
- на «чистых» БД, где 30b90143856c уже применила refresh_tokens без family/
  parent/revoked, ветка v1.1 не могла примениться вообще (таблицы нет на старте);
- порядок применения Alembic гарантирует, что к этому моменту обе предки-ветки
  выполнены; здесь мы лишь досоздаём недостающие колонки ротации семейств
  токенов (Этап 2.4 ТЗ) идемпотентно — через reflection inspector, чтобы
  миграция была безопасна на любом диалекте и любом состоянии схемы.

После этой ревизии у репозитория ровно ОДИН head. Проверка:
    python server/merge_heads.py --check   (или alembic heads)
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f7a8b9cafed0"
# Жёсткое слияние ДВУХ текущих heads в один граф:
down_revision: Union[str, Sequence[str], None] = ("30b90143856c", "e6f7a8b9cafe")
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _existing_columns(table: str) -> set:
    """Имена колонок таблицы в ТЕКУЩЕМ состоянии БД (диалект-agnostically)."""
    conn = op.get_bind()
    insp = sa.inspect(conn)
    if table not in insp.get_table_names():
        return set()
    return {c["name"] for c in insp.get_columns(table)}


def upgrade() -> None:
    # --- 0) Идемпотентный ремонт легаси-ветки a1b2c3d4e5f6 на SQLite.
    # Initial-миграция (80b0e94ce7e3) уже создаёт users.username (+UNIQUE) и
    # verify_codes.target, а a1b2c3d4e5f6 безусловно их ADD COLUMN — на чистых
    # БД это падало с 'duplicate column name' (подтверждено прогоном
    # `alembic upgrade head` на fresh SQLite). Правка идемпотентности здесь,
    # а не правкой истории применённых ревизий: БД, где ветка уже прошла,
    # остаются консистентны.
    user_cols = _existing_columns("users")
    if "username" not in user_cols:
        op.add_column("users", sa.Column("username", sa.String(32), nullable=True))
        op.create_index("ix_users_username", "users", ["username"], unique=True)
    else:
        idx = {i["name"] for i in sa.inspect(op.get_bind()).get_indexes("users")}
        if "ix_users_username" not in idx:
            op.create_index("ix_users_username", "users", ["username"], unique=True)

    vc_cols = _existing_columns("verify_codes")
    if "target" not in vc_cols:
        op.add_column("verify_codes", sa.Column("target", sa.String(), nullable=True))

    existing = _existing_columns("refresh_tokens")

    # 1) refresh_tokens должна существовать на обеих ветках; если легаси-БД
    #    мигрировала мимо 30b90143856c (ручной bootstrap), создаём её here.
    if "token" not in existing:
        op.create_table(
            "refresh_tokens",
            sa.Column("token", sa.String(), nullable=False),
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.Column("expires_at", sa.DateTime(), nullable=False),
            sa.Column("created_at", sa.DateTime(),
                      server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("token"),
        )
        op.create_index("idx_refresh_tokens_user", "refresh_tokens", ["user_id"])
        existing = _existing_columns("refresh_tokens")

    # 2) Колонки ротации семейств (Этап 2.4) — добавляем только отсутствующие:
    #    ветка c4d5e6f7a8b9 уже внесла их там, где она прошла до merge.
    if "family" not in existing:
        op.add_column("refresh_tokens", sa.Column("family", sa.String(64), nullable=True))
    if "parent" not in existing:
        op.add_column("refresh_tokens", sa.Column("parent", sa.String(128), nullable=True))
    if "revoked" not in existing:
        op.add_column(
            "refresh_tokens",
            sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
        )

    idx_family = {i["name"] for i in sa.inspect(op.get_bind()).get_indexes("refresh_tokens")}
    if "idx_refresh_tokens_family" not in idx_family:
        op.create_index("idx_refresh_tokens_family", "refresh_tokens", ["family"])

    # 3) Backfill семейств для токенов, появившихся до внедрения ротации.
    #    md5/random специфичны для PG — используем portable-выражение: SQLite
    #    не знает random()::text, поэтому генерируем значение на Python-side
    #    через SQL-standard hex(randomblob(...))/lower(hex(...)) нельзя
    #    единообразно — делаем детерминированный UUID из token на Python.
    import uuid

    bind = op.get_bind()
    rows = bind.execute(sa.text(
        "SELECT token FROM refresh_tokens WHERE family IS NULL"
    )).fetchall()
    for (token,) in rows:
        fam = uuid.uuid5(uuid.NAMESPACE_OID, f"meno-legacy-family:{token}").hex[:24]
        bind.execute(
            sa.text("UPDATE refresh_tokens SET family = :fam WHERE token = :tok"),
            {"fam": fam, "tok": token},
        )


def downgrade() -> None:
    """Откат merge-ревизии возвращает граф к двум heads (не удаляя данные веток).

    Колонки ротации принадлежат ветке c4d5e6f7a8b9 — при downgrade до неё они
    будут убраны её же reverse-операцией, поэтому здесь только снятие
    маркера слияния (no-op для схемы). Явное исключение: если таблица была
    создана этим merge (легаси-обход), оставляем её — удаление данных токенов
    требует отдельного осознанного решения администратора.
    """
    pass
