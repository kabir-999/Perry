"""scan test-results matrix column

Revision ID: 5d4e6f708192
Revises: 4c3d5e6f7081
Create Date: 2026-08-11
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "5d4e6f708192"
down_revision: Union[str, None] = "4c3d5e6f7081"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("test_results_json", sa.Text(), nullable=False, server_default=""),
    )
    op.alter_column("scans", "test_results_json", server_default=None)


def downgrade() -> None:
    op.drop_column("scans", "test_results_json")
