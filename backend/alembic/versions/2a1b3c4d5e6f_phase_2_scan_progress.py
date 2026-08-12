"""phase 2 two-stage scan progress columns

Revision ID: 2a1b3c4d5e6f
Revises: 10e53f8c2ea9
Create Date: 2026-08-11

Adds fast-scan result + live deep-scan progress counters to `scans`.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "2a1b3c4d5e6f"
down_revision: Union[str, None] = "10e53f8c2ea9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_STR_COLUMNS = [
    ("fast_result_json", sa.Text()),
    ("initial_risk", sa.String(length=16)),
    ("final_risk", sa.String(length=16)),
    ("ai_status", sa.String(length=128)),
    ("checks_done_json", sa.Text()),
]

_INT_COLUMNS = [
    "deep_progress",
    "urls_discovered",
    "apis_discovered",
    "parameters_discovered",
    "subdomains_discovered",
    "security_checks_completed",
    "findings_count",
]


def upgrade() -> None:
    for name, coltype in _STR_COLUMNS:
        op.add_column(
            "scans",
            sa.Column(name, coltype, nullable=False, server_default=""),
        )
    for name in _INT_COLUMNS:
        op.add_column(
            "scans",
            sa.Column(name, sa.Integer(), nullable=False, server_default="0"),
        )
    # Drop the server_defaults now that existing rows are backfilled; the
    # ORM supplies defaults for new rows.
    for name, _ in _STR_COLUMNS:
        op.alter_column("scans", name, server_default=None)
    for name in _INT_COLUMNS:
        op.alter_column("scans", name, server_default=None)


def downgrade() -> None:
    for name in _INT_COLUMNS:
        op.drop_column("scans", name)
    for name, _ in _STR_COLUMNS:
        op.drop_column("scans", name)
