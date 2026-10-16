"""Auth without phone: add users.username, verify_codes.target

Перевод аутентификации с телефона/SMS на username + пароль.
Старые колонки `phone` оставлены nullable для совместимости с существующими БД.

Revision ID: a1b2c3d4e5f6
Revises: 80b0e94ce7e3
Create Date: 2026-10-16
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = '80b0e94ce7e3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # users.username — уникальный логин вместо телефона
    op.add_column('users', sa.Column('username', sa.String(length=32), nullable=True))
    op.create_index(op.f('ix_users_username'), 'users', ['username'], unique=True)

    # Миграция данных: старые аккаунты получают username из display_name/id.
    op.execute(
        """
        UPDATE users
        SET username = COALESCE(
            NULLIF(regexp_replace(COALESCE(display_name, ''), '[^a-zA-Z0-9_.]', '', 'g'), ''),
            'user_' || id::text
        )
        WHERE username IS NULL
        """
    )
    # Гарантируем уникальность: дубликаты помечаем суффиксом по id
    op.execute(
        """
        UPDATE users u
        SET username = u.username || '_' || u.id::text
        WHERE EXISTS (
            SELECT 1 FROM users v
            WHERE v.username = u.username AND v.id < u.id
        )
        """
    )

    # phone больше не обязателен
    op.alter_column('users', 'phone', existing_type=sa.String(), nullable=True)

    # verify_codes: target (email/username) вместо обязательного phone (legacy)
    op.add_column('verify_codes', sa.Column('target', sa.String(), nullable=True))
    op.alter_column('verify_codes', 'phone', existing_type=sa.String(), nullable=True)


def downgrade() -> None:
    op.drop_column('verify_codes', 'target')
    op.drop_index(op.f('ix_users_username'), table_name='users')
    op.drop_column('users', 'username')
