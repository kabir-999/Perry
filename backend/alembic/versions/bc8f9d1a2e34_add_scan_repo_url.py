"""Add user-supplied repo_url to scans

Revision ID: bc8f9d1a2e34
Revises: ab7e7c5e64ed
Create Date: 2026-08-12 00:45:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'bc8f9d1a2e34'
down_revision: Union[str, None] = 'ab7e7c5e64ed'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'scans',
        sa.Column('repo_url', sa.String(length=2048), nullable=False, server_default=''),
    )


def downgrade() -> None:
    op.drop_column('scans', 'repo_url')
