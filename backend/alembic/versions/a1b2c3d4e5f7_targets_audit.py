"""Verified targets, audit log, scan classification

Revision ID: a1b2c3d4e5f7
Revises: f1a2b3c4d5e6
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = 'a1b2c3d4e5f7'
down_revision: Union[str, None] = 'f1a2b3c4d5e6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'verified_targets',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('hostname', sa.String(length=255), nullable=False),
        sa.Column('verification_status', sa.String(length=32), nullable=False, server_default='UNVERIFIED'),
        sa.Column('verification_method', sa.String(length=16), nullable=False, server_default=''),
        sa.Column('verification_token', sa.String(length=128), nullable=False),
        sa.Column('last_error', sa.Text(), nullable=False, server_default=''),
        sa.Column('verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('verification_expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('active_testing_enabled', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_verified_targets_user_id', 'verified_targets', ['user_id'])
    op.create_index('ix_verified_targets_hostname', 'verified_targets', ['hostname'])

    op.create_table(
        'audit_logs',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('action', sa.String(length=64), nullable=False),
        sa.Column('target', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('result', sa.String(length=32), nullable=False, server_default=''),
        sa.Column('detail', sa.Text(), nullable=False, server_default=''),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_audit_logs_user_id', 'audit_logs', ['user_id'])
    op.create_index('ix_audit_logs_action', 'audit_logs', ['action'])

    op.add_column('scans', sa.Column('scan_type', sa.String(length=32), nullable=False, server_default='PASSIVE_WEB'))
    op.add_column('scans', sa.Column('authorization_status', sa.String(length=32), nullable=False, server_default='UNVERIFIED'))


def downgrade() -> None:
    op.drop_column('scans', 'authorization_status')
    op.drop_column('scans', 'scan_type')
    op.drop_table('audit_logs')
    op.drop_table('verified_targets')
