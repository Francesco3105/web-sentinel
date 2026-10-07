"""raise the default http check timeout from 10 to 120 seconds

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-06
"""
from alembic import op

revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Only checks still on the old default; values changed by hand are left alone.
    op.execute("UPDATE checks SET timeout_seconds = 120 WHERE type = 'http' AND timeout_seconds = 10")


def downgrade() -> None:
    op.execute("UPDATE checks SET timeout_seconds = 10 WHERE type = 'http' AND timeout_seconds = 120")
