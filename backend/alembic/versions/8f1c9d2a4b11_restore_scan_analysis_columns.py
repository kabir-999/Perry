"""restore scan analysis columns

Revision ID: 8f1c9d2a4b11
Revises: d2e3f4a5b6c7
Create Date: 2026-08-17

Reintroduce the scan-level analysis payload so Perry can persist the backend
summary, recommendation, and risk-factor notes again.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "8f1c9d2a4b11"
down_revision: Union[str, None] = "d2e3f4a5b6c7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("ai_analyzed", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "scans",
        sa.Column("ai_error", sa.Text(), nullable=False, server_default=""),
    )
    op.add_column(
        "scans",
        sa.Column("ai_summary", sa.Text(), nullable=False, server_default=""),
    )
    op.add_column(
        "scans",
        sa.Column("ai_recommendation", sa.Text(), nullable=False, server_default=""),
    )
    op.add_column(
        "scans",
        sa.Column("risk_factors_json", sa.Text(), nullable=False, server_default=""),
    )
    op.alter_column("scans", "ai_analyzed", server_default=None)
    op.alter_column("scans", "ai_error", server_default=None)
    op.alter_column("scans", "ai_summary", server_default=None)
    op.alter_column("scans", "ai_recommendation", server_default=None)
    op.alter_column("scans", "risk_factors_json", server_default=None)


def downgrade() -> None:
    op.drop_column("scans", "risk_factors_json")
    op.drop_column("scans", "ai_recommendation")
    op.drop_column("scans", "ai_summary")
    op.drop_column("scans", "ai_error")
    op.drop_column("scans", "ai_analyzed")
