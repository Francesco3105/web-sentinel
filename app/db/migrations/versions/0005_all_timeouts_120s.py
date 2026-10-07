"""raise the dns, tls and domain check timeouts to 120 seconds

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-06
"""
from alembic import op

revision = '0005'
down_revision = '0004'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Only checks still on the old defaults; values changed by hand are left alone.
    op.execute(
        "UPDATE checks SET timeout_seconds = 120 "
        "WHERE (type IN ('dns', 'tls') AND timeout_seconds = 10) "
        "OR (type = 'domain' AND timeout_seconds = 20)"
    )


def downgrade() -> None:
    op.execute(
        "UPDATE checks SET timeout_seconds = 10 "
        "WHERE type IN ('dns', 'tls') AND timeout_seconds = 120"
    )
    op.execute("UPDATE checks SET timeout_seconds = 20 WHERE type = 'domain' AND timeout_seconds = 120")
