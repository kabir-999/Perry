"""Add evidence fields (parameter_location, auth_context, reproducibility) to findings

Revision ID: b7c6d5e4f3a2
Revises: a9b8c7d6e5f4
Create Date: 2026-08-13 00:00:00.000002

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = 'b7c6d5e4f3a2'
down_revision: Union[str, None] = 'a9b8c7d6e5f4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('findings', sa.Column('parameter_location', sa.String(32), nullable=False, server_default=''))
    op.add_column('findings', sa.Column('auth_context', sa.String(128), nullable=False, server_default=''))
    op.add_column('findings', sa.Column('reproducibility', sa.String(256), nullable=False, server_default=''))


def downgrade() -> None:
    op.drop_column('findings', 'reproducibility')
    op.drop_column('findings', 'auth_context')
    op.drop_column('findings', 'parameter_location')
