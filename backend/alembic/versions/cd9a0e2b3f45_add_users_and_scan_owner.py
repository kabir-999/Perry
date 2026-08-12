"""Add users table and scan ownership

Revision ID: cd9a0e2b3f45
Revises: bc8f9d1a2e34
Create Date: 2026-08-12 01:20:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = 'cd9a0e2b3f45'
down_revision: Union[str, None] = 'bc8f9d1a2e34'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('email', sa.String(length=320), nullable=False),
        sa.Column('password_hash', sa.String(length=128), nullable=False),
        sa.Column('display_name', sa.String(length=120), nullable=False, server_default=''),
        sa.Column('role', sa.String(length=16), nullable=False, server_default='customer'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)

    # Nullable: scans created before accounts existed have no owner.
    op.add_column(
        'scans',
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_index(op.f('ix_scans_user_id'), 'scans', ['user_id'])
    op.create_foreign_key(
        'fk_scans_user_id_users', 'scans', 'users', ['user_id'], ['id'],
        ondelete='CASCADE',
    )


def downgrade() -> None:
    op.drop_constraint('fk_scans_user_id_users', 'scans', type_='foreignkey')
    op.drop_index(op.f('ix_scans_user_id'), table_name='scans')
    op.drop_column('scans', 'user_id')
    op.drop_index(op.f('ix_users_email'), table_name='users')
    op.drop_table('users')
