"""ai assessment state columns

Revision ID: 4c3d5e6f7081
Revises: 3b2c4d5e6f70
Create Date: 2026-08-11

Adds the AI-analyzed flag, unavailability reason, and the Groq risk-factors
payload so the risk score/level are authoritative only when Groq validated.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "4c3d5e6f7081"
down_revision: Union[str, None] = "3b2c4d5e6f70"
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
        sa.Column("risk_factors_json", sa.Text(), nullable=False, server_default=""),
    )
    op.alter_column("scans", "ai_analyzed", server_default=None)
    op.alter_column("scans", "ai_error", server_default=None)
    op.alter_column("scans", "risk_factors_json", server_default=None)


def downgrade() -> None:
    op.drop_column("scans", "risk_factors_json")
    op.drop_column("scans", "ai_error")
    op.drop_column("scans", "ai_analyzed")
