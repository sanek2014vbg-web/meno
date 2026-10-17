"""Push outbox (long-polling fallback) + индексы сообщений (Этапы 3.3, 4.1, 4.5)

Revision ID: d5e6f7a8b9ca
Revises: c4d5e6f7a8b9
Create Date: 2026-10-17
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'd5e6f7a8b9ca'
down_revision: Union[str, Sequence[str], None] = 'c4d5e6f7a8b9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'push_outbox',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('title', sa.String(200), server_default=''),
        sa.Column('body', sa.String(500), server_default=''),
        sa.Column('data', sa.Text(), server_default='{}'),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_push_outbox_user', 'push_outbox', ['user_id', 'id'])

    # Идемпотентность отправки: один client_id не повторяется в чате
    op.create_index('uq_messages_chat_client', 'messages', ['chat_id', 'client_id'], unique=True)
    # Быстрая история чата (курсорная пагинация)
    op.create_index('idx_messages_chat_created', 'messages', ['chat_id', 'created_at'])


def downgrade() -> None:
    op.drop_index('idx_messages_chat_created', table_name='messages')
    op.drop_index('uq_messages_chat_client', table_name='messages')
    op.drop_index('idx_push_outbox_user', table_name='push_outbox')
    op.drop_table('push_outbox')
