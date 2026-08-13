"""Add optional dev-supplied credential to VerifiedTarget for authz differential testing

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f7
Create Date: 2026-08-13 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = 'b2c3d4e5f6a7'
down_revision: Union[str, None] = 'a1b2c3d4e5f7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Nullable — most targets have no credential. Never written to
    # audit_logs; only set/read by the owning developer via /targets API.
    op.add_column(
        'verified_targets',
        sa.Column('auth_header', sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column('verified_targets', 'auth_header')
