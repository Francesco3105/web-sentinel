"""run http checks every 5 minutes and dns checks every 10 minutes

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-06
"""
from alembic import op

revision = '0004'
down_revision = '0003'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Only checks still on the old defaults; values changed by hand are left alone.
    op.execute("UPDATE checks SET interval_seconds = 600 WHERE type = 'dns' AND interval_seconds = 300")
    op.execute("UPDATE checks SET interval_seconds = 300 WHERE type = 'http' AND interval_seconds = 60")


def downgrade() -> None:
    op.execute("UPDATE checks SET interval_seconds = 60 WHERE type = 'http' AND interval_seconds = 300")
    op.execute("UPDATE checks SET interval_seconds = 300 WHERE type = 'dns' AND interval_seconds = 600")
