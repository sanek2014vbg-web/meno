"""Auth without phone: add users.username, verify_codes.target

Перевод аутентификации с телефона/SMS на username + пароль.
Старые колонки `phone` оставлены nullable для совместимости с существующими БД.

Ревизия переписана (файл на месте, id не меняется) в идемпотентную форму:
initial-миграция 80b0e94ce7e3 уже создаёт users.username (+UNIQUE) и
verify_codes.target, поэтому безусловный ADD COLUMN падал на чистых БД с
ошибкой 'duplicate column name'. Данные теперь бэкфиллятся переносимо между
SQLite и PostgreSQL (ранее использовался PG-специфичный regexp_replace — A13).

Revision ID: a1b2c3d4e5f6
Revises: 80b0e94ce7e3
Create Date: 2026-10-16 (idempotency rewrite: 2026-10-17)
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = '80b0e94ce7e3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _table_exists(table: str) -> bool:
    return table in sa.inspect(op.get_bind()).get_table_names()


def _existing_columns(table: str) -> set:
    if not _table_exists(table):
        return set()
    return {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def _existing_indexes(table: str) -> set:
    insp = sa.inspect(op.get_bind())
    if table not in insp.get_table_names():
        return set()
    names = {i["name"] for i in insp.get_indexes(table)}
    # PK-автостеки UNIQUE-констрейнтов SQLite в get_indexes не видны;
    # для ix_users_username это не критично: дубль имени индекса ниже guarded.
    return names


def upgrade() -> None:
    bind = op.get_bind()

    # --- users.username (идемпотентно: initial уже содержит колонку) ---
    user_cols = _existing_columns("users")
    if "username" not in user_cols:
        op.add_column('users', sa.Column('username', sa.String(length=32), nullable=True))
    if "ix_users_username" not in _existing_indexes("users"):
        op.create_index('ix_users_username', 'users', ['username'], unique=True)

    # Миграция данных: старые аккаунты получают username из display_name/id.
    # Переносимо: санация символов и уникализация делаемы на Python-side,
    # без PG-специфичных regexp_replace/::text (дефект A13).
    rows = bind.execute(sa.text(
        "SELECT id, display_name FROM users WHERE username IS NULL ORDER BY id"
    )).fetchall()
    taken = {
        r[0] for r in bind.execute(
            sa.text("SELECT username FROM users WHERE username IS NOT NULL")
        ).fetchall()
    }
    for uid, display_name in rows:
        base = "".join(
            ch for ch in (display_name or "") if ch.isalnum() or ch in ("_", ".")
        )[:24] or f"user_{uid}"
        candidate, n = base, 0
        while candidate.lower() in taken:
            n += 1
            candidate = f"{base}_{uid}" if n == 1 else f"{base}_{uid}_{n}"
        taken.add(candidate.lower())
        bind.execute(
            sa.text("UPDATE users SET username = :u WHERE id = :i"),
            {"u": candidate, "i": uid},
        )

    # Гарантируем уникальность уже существовавших дубликатов (легаси-БД без
    # констрейнта): помечаем суффиксом по id, тоже переносимо.
    dups = bind.execute(sa.text(
        "SELECT u.id, u.username FROM users u JOIN users v "
        "ON u.username = v.username AND v.id < u.id WHERE u.username IS NOT NULL"
    )).fetchall()
    for uid, uname in dups:
        bind.execute(
            sa.text("UPDATE users SET username = :u WHERE id = :i"),
            {"u": f"{uname}_{uid}", "i": uid},
        )

    # phone больше не обязателен (только если реально NOT NULL)
    cols_meta = {c["name"]: c for c in sa.inspect(bind).get_columns("users")}
    if not cols_meta.get("phone", {}).get("nullable", True):
        op.alter_column('users', 'phone', existing_type=sa.String(), nullable=True)

    # --- verify_codes.target (идемпотентно) ---
    vc_cols = _existing_columns("verify_codes")
    if "target" not in vc_cols:
        op.add_column('verify_codes', sa.Column('target', sa.String(), nullable=True))
    vc_meta = {c["name"]: c for c in sa.inspect(bind).get_columns("verify_codes")}
    if vc_cols and not vc_meta.get("phone", {}).get("nullable", True):
        op.alter_column('verify_codes', 'phone', existing_type=sa.String(), nullable=True)


def downgrade() -> None:
    # Колонки удаляем только если они существуют (симметрия идемпотентности).
    if "target" in _existing_columns("verify_codes"):
        op.drop_column('verify_codes', 'target')
    if "ix_users_username" in _existing_indexes("users"):
        op.drop_index('ix_users_username', table_name='users')
    if "username" in _existing_columns("users"):
        op.drop_column('users', 'username')
