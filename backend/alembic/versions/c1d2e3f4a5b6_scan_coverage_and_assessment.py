"""Add coverage metrics and coverage-aware overall risk/confidence to scans

Revision ID: c1d2e3f4a5b6
Revises: b7c6d5e4f3a2
Create Date: 2026-08-13 00:00:00.000003

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = 'c1d2e3f4a5b6'
down_revision: Union[str, None] = 'b7c6d5e4f3a2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('scans', sa.Column('coverage_json', sa.Text(), nullable=False, server_default=''))
    op.add_column('scans', sa.Column('overall_risk', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('scans', sa.Column('assessment_confidence', sa.String(32), nullable=False, server_default=''))
    op.add_column('scans', sa.Column('assessment_coverage', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('scans', sa.Column('assessment_warning', sa.Text(), nullable=False, server_default=''))


def downgrade() -> None:
    op.drop_column('scans', 'assessment_warning')
    op.drop_column('scans', 'assessment_coverage')
    op.drop_column('scans', 'assessment_confidence')
    op.drop_column('scans', 'overall_risk')
    op.drop_column('scans', 'coverage_json')
