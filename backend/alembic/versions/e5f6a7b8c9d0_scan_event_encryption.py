"""Encrypt scan_events.message at rest via pgcrypto, index created_at for retention sweeps

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-08-13 00:20:00.000000

"""
import os
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = 'e5f6a7b8c9d0'
down_revision: Union[str, None] = 'd4e5f6a7b8c9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    # Add the new encrypted column alongside the old plaintext one, backfill
    # by encrypting existing rows with the current LOG_ENCRYPTION_KEY (read
    # from the environment at migration time — never embedded in this file
    # or in migration history), then swap.
    op.add_column("scan_events", sa.Column("message_encrypted", sa.LargeBinary(), nullable=True))

    key = os.environ.get("LOG_ENCRYPTION_KEY", "dev-only-change-me-log-key")
    op.execute(
        sa.text(
            "UPDATE scan_events SET message_encrypted = pgp_sym_encrypt(message, :key)"
        ).bindparams(key=key)
    )

    op.drop_column("scan_events", "message")
    op.alter_column("scan_events", "message_encrypted", new_column_name="message")

    op.create_index("ix_scan_events_created_at", "scan_events", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_scan_events_created_at", table_name="scan_events")

    op.add_column("scan_events", sa.Column("message_plain", sa.Text(), nullable=True))
    key = os.environ.get("LOG_ENCRYPTION_KEY", "dev-only-change-me-log-key")
    op.execute(
        sa.text(
            "UPDATE scan_events SET message_plain = pgp_sym_decrypt(message, :key)"
        ).bindparams(key=key)
    )
    op.drop_column("scan_events", "message")
    op.alter_column("scan_events", "message_plain", new_column_name="message")
