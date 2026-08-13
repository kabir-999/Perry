"""Add fingerprint to findings for rescan/remediation-verification tracking

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-08-13 00:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = 'd4e5f6a7b8c9'
down_revision: Union[str, None] = 'c3d4e5f6a7b8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'findings',
        sa.Column('fingerprint', sa.String(length=512), nullable=False,
                  server_default=''),
    )
    op.create_index('ix_findings_fingerprint', 'findings', ['fingerprint'])


def downgrade() -> None:
    op.drop_index('ix_findings_fingerprint', table_name='findings')
    op.drop_column('findings', 'fingerprint')
