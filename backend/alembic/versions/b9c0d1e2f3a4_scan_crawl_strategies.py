"""Add per-strategy (BFS/DFS) crawl layer column to scans

Revision ID: b9c0d1e2f3a4
Revises: a8b9c0d1e2f3
Create Date: 2026-08-15 00:00:00.000003

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = 'b9c0d1e2f3a4'
down_revision: Union[str, None] = 'a8b9c0d1e2f3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("crawl_strategies_json", sa.Text(), nullable=False, server_default=""),
    )


def downgrade() -> None:
    op.drop_column("scans", "crawl_strategies_json")
