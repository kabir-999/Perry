"""Add second scanner credential (two-account IDOR testing) and opt-in authenticated-scan flag

Revision ID: a9b8c7d6e5f4
Revises: e5f6a7b8c9d0
Create Date: 2026-08-13 00:00:00.000001

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = 'a9b8c7d6e5f4'
down_revision: Union[str, None] = 'e5f6a7b8c9d0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'verified_targets',
        sa.Column('auth_header_b', sa.Text(), nullable=True),
    )
    op.add_column(
        'scans',
        sa.Column('authenticated_scan', sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column('scans', 'authenticated_scan')
    op.drop_column('verified_targets', 'auth_header_b')
