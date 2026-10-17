"""Полнотекстовый поиск с кириллицей: tsvector-колонка + GIN (PostgreSQL only, Этап 4.2)

На SQLite миграция no-op: поиск деградирует до LIKE (диалект-безопасно).

Revision ID: e6f7a8b9cafe
Revises: d5e6f7a8b9ca
Create Date: 2026-10-17
"""
from typing import Sequence, Union

from alembic import op

revision: str = 'e6f7a8b9cafe'
down_revision: Union[str, Sequence[str], None] = 'd5e6f7a8b9ca'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
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
    # Заполняем колонку для существующих строк
    op.execute("""
        UPDATE messages SET search_vector = to_tsvector('russian', COALESCE(content, ''))
        WHERE search_vector IS NULL;
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_messages_search ON messages USING GIN (search_vector)")


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    op.execute("DROP INDEX IF EXISTS idx_messages_search")
    op.execute("DROP TRIGGER IF EXISTS trg_meno_messages_search ON messages")
    op.execute("DROP FUNCTION IF EXISTS meno_messages_search_trigger()")
    op.execute("ALTER TABLE messages DROP COLUMN IF EXISTS search_vector")
