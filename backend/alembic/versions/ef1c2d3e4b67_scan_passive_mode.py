"""Add passive_only scan mode

Revision ID: ef1c2d3e4b67
Revises: de0b1c3d4a56
Create Date: 2026-08-12 02:40:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = 'ef1c2d3e4b67'
down_revision: Union[str, None] = 'de0b1c3d4a56'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Existing scans all ran with authorization confirmed, so False is right.
    op.add_column('scans', sa.Column('passive_only', sa.Boolean(), nullable=False,
                                     server_default=sa.false()))


def downgrade() -> None:
    op.drop_column('scans', 'passive_only')
