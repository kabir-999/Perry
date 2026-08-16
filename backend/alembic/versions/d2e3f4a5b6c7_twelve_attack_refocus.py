"""Refocus to 12-attack dynamic scanner: drop source-analysis + AI + old-risk columns/tables, add attack matrix/coverage

Revision ID: d2e3f4a5b6c7
Revises: c1d2e3f4a5b6
Create Date: 2026-08-14 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = 'd2e3f4a5b6c7'
down_revision: Union[str, None] = 'c1d2e3f4a5b6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SCAN_DROP = [
    "repo_info_json", "repo_url", "custom_test_cases_json",
    "ai_analyzed", "ai_error", "ai_summary", "ai_recommendation",
    "risk_factors_json", "test_results_json", "Perry_risk_json",
]
_FINDING_DROP = [
    "llm_verdict", "llm_confidence", "llm_explanation", "llm_false_positive_reason",
]


def upgrade() -> None:
    op.add_column("scans", sa.Column("attack_matrix_json", sa.Text(), nullable=False, server_default=""))
    op.add_column("scans", sa.Column("attack_coverage_json", sa.Text(), nullable=False, server_default=""))

    for col in _SCAN_DROP:
        op.drop_column("scans", col)
    for col in _FINDING_DROP:
        op.drop_column("findings", col)

    op.drop_table("source_findings")
    op.drop_table("repositories")


def downgrade() -> None:
    # Recreate the dropped tables minimally and restore columns (defaults only;
    # historical source/AI data is not recoverable).
    op.create_table(
        "repositories",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", sa.dialects.postgresql.UUID(as_uuid=True)),
    )
    op.create_table(
        "source_findings",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", sa.dialects.postgresql.UUID(as_uuid=True)),
    )
    for col in _FINDING_DROP:
        op.add_column("findings", sa.Column(col, sa.Text(), nullable=True))
    for col in _SCAN_DROP:
        op.add_column("scans", sa.Column(col, sa.Text(), nullable=False, server_default=""))
    op.drop_column("scans", "attack_coverage_json")
    op.drop_column("scans", "attack_matrix_json")
