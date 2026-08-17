"""merge scan analysis and crawl heads

Revision ID: 9c2d1e3f4a5b
Revises: 8f1c9d2a4b11, b9c0d1e2f3a4
Create Date: 2026-08-17

Merge the two alembic heads back into a single linear upgrade path.
"""
from typing import Sequence, Union

from alembic import op


revision: str = "9c2d1e3f4a5b"
down_revision: Union[str, tuple[str, str], None] = (
    "8f1c9d2a4b11",
    "b9c0d1e2f3a4",
)
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
