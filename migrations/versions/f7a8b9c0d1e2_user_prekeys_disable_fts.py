"""Prekey Bundle (X3DH) + отключение серверного полнотекстового поиска (Пункт 1 ТЗ v2.0)

Создаёт таблицу ``user_prekeys`` для хранения публичных ключей Signal-протокола:
Identity Key, Signed Prekey и пул One-Time Prekeys (приватные части на сервере
не хранятся — сервер физически не может расшифровать сообщения).

Одновременно удаляет инфраструктуру FTS из PostgreSQL (колонку search_vector,
триггер meno_messages_search_trigger и GIN-индекс): при E2E-шифровании контент
в БД — слепой ciphertext, индексация бессмысленна и нежелательна. Поиск
переносится в локальную SQLite клиента (FTS5 по дешифрованному тексту).

На SQLite миграция создания таблицы идентична; удаление FTS — no-op
(инфраструктура создавалась только на PG, см. миграцию e6f7a8b9cafe).

Revision ID: f7a8b9c0d1e2
Revises: e6f7a8b9cafe
Create Date: 2026-10-18
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'f7a8b9c0d1e2'
down_revision: Union[str, Sequence[str], None] = 'e6f7a8b9cafe'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- 1. Таблица user_prekeys (Prekey Bundle X3DH) ---
    op.create_table(
        'user_prekeys',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('key_type', sa.String(16), nullable=False),
        sa.Column('key_id', sa.Integer(), server_default='0', nullable=False),
        sa.Column('public_key', sa.Text(), nullable=False),
        sa.Column('signature', sa.Text(), nullable=True),
        sa.Column('consumed', sa.Boolean(), server_default='0', nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    # Частичные уникальные индексы: у пользователя ровно один identity,
    # один signed prekey и неповторяющиеся key_id among one-time prekeys.
    op.create_index(
        'uq_user_prekeys_identity', 'user_prekeys', ['user_id', 'key_type'],
        unique=True, postgresql_where=sa.text("key_type = 'identity'"),
        sqlite_where=sa.text("key_type = 'identity'"),
    )
    op.create_index(
        'uq_user_prekeys_signed', 'user_prekeys', ['user_id', 'key_type'],
        unique=True, postgresql_where=sa.text("key_type = 'signed'"),
        sqlite_where=sa.text("key_type = 'signed'"),
    )
    op.create_index(
        'uq_user_prekeys_onetime', 'user_prekeys', ['user_id', 'key_id'],
        unique=True, postgresql_where=sa.text("key_type = 'one_time'"),
        sqlite_where=sa.text("key_type = 'one_time'"),
    )
    op.create_index('idx_user_prekeys_lookup', 'user_prekeys',
                    ['user_id', 'key_type', 'consumed'])

    # --- 2. Отключение серверного FTS (PostgreSQL only) ---
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("DROP INDEX IF EXISTS idx_messages_search")
        op.execute("DROP TRIGGER IF EXISTS trg_meno_messages_search ON messages")
        op.execute("DROP FUNCTION IF EXISTS meno_messages_search_trigger()")
        op.execute("ALTER TABLE messages DROP COLUMN IF EXISTS search_vector")


def downgrade() -> None:
    op.drop_index('idx_user_prekeys_lookup', table_name='user_prekeys')
    op.drop_index('uq_user_prekeys_onetime', table_name='user_prekeys')
    op.drop_index('uq_user_prekeys_signed', table_name='user_prekeys')
    op.drop_index('uq_user_prekeys_identity', table_name='user_prekeys')
    op.drop_table('user_prekeys')

    # Возврат FTS-инфраструктуры (только PG) — для отката на plaintext-режим.
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("ALTER TABLE messages ADD COLUMN IF NOT EXISTS search_vector tsvector")
        op.execute("""
            CREATE OR REPLACE FUNCTION meno_messages_search_trigger() RETURNS trigger AS $$
            BEGIN
              NEW.search_vector := to_tsvector('russian', COALESCE(NEW.content, ''));
              RETURN NEW;
            END
            $$ LANGUAGE plpgsql;
        """)
        op.execute("""
            DROP TRIGGER IF EXISTS trg_meno_messages_search ON messages;
            CREATE TRIGGER trg_meno_messages_search
            BEFORE INSERT OR UPDATE OF content ON messages
            FOR EACH ROW EXECUTE FUNCTION meno_messages_search_trigger();
        """)
        op.execute("""
            UPDATE messages SET search_vector = to_tsvector('russian', COALESCE(content, ''))
            WHERE search_vector IS NULL;
        """)
        op.execute("CREATE INDEX IF NOT EXISTS idx_messages_search ON messages USING GIN (search_vector)")
