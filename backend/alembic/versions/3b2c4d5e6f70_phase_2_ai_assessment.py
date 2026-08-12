"""phase 2 overall AI assessment columns

Revision ID: 3b2c4d5e6f70
Revises: 2a1b3c4d5e6f
Create Date: 2026-08-11

Adds the overall risk score + AI Security Analyst narrative shown on the
single Scan Detail page.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "3b2c4d5e6f70"
down_revision: Union[str, None] = "2a1b3c4d5e6f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "scans",
        sa.Column("ai_summary", sa.Text(), nullable=False, server_default=""),
    )
    op.add_column(
        "scans",
        sa.Column("ai_recommendation", sa.Text(), nullable=False, server_default=""),
    )
    op.alter_column("scans", "risk_score", server_default=None)
    op.alter_column("scans", "ai_summary", server_default=None)
    op.alter_column("scans", "ai_recommendation", server_default=None)


def downgrade() -> None:
    op.drop_column("scans", "ai_recommendation")
    op.drop_column("scans", "ai_summary")
    op.drop_column("scans", "risk_score")
