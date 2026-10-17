"""Refresh sessions: family + parent + revoked (ротация и детекция переиспользования, Этап 2.4)

Revision ID: c4d5e6f7a8b9
Revises: a1b2c3d4e5f6
Create Date: 2026-10-17
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'c4d5e6f7a8b9'
down_revision: Union[str, Sequence[str], None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('refresh_tokens', sa.Column('family', sa.String(64), nullable=True))
    op.add_column('refresh_tokens', sa.Column('parent', sa.String(128), nullable=True))
    op.add_column('refresh_tokens', sa.Column('revoked', sa.Boolean(), nullable=False,
                                              server_default=sa.false()))
    op.create_index('idx_refresh_tokens_family', 'refresh_tokens', ['family'])
    # Существующие токены получают собственную семью
    op.execute("UPDATE refresh_tokens SET family = substr(md5(random()::text || token), 1, 24) WHERE family IS NULL")


def downgrade() -> None:
    op.drop_index('idx_refresh_tokens_family', table_name='refresh_tokens')
    op.drop_column('refresh_tokens', 'revoked')
    op.drop_column('refresh_tokens', 'parent')
    op.drop_column('refresh_tokens', 'family')
