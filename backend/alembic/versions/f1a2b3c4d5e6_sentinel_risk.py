"""Add Perry Risk Model output to scans

Revision ID: f1a2b3c4d5e6
Revises: ef1c2d3e4b67
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'f1a2b3c4d5e6'
down_revision: Union[str, None] = 'ef1c2d3e4b67'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('scans', sa.Column('Perry_risk_json', sa.Text(),
                                     nullable=False, server_default=''))


def downgrade() -> None:
    op.drop_column('scans', 'Perry_risk_json')
