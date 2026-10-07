"""raise the default http slow-response threshold from 2 to 30 seconds

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-06
"""
import sqlalchemy as sa
from alembic import op

revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None

checks = sa.table(
    'checks',
    sa.column('id', sa.Integer),
    sa.column('type', sa.String),
    sa.column('thresholds', sa.JSON),
)


def _replace(old: int, new: int) -> None:
    # Only checks still on the old default; values changed by hand are left alone.
    bind = op.get_bind()
    rows = bind.execute(sa.select(checks.c.id, checks.c.thresholds).where(checks.c.type == 'http'))
    for check_id, thresholds in rows.fetchall():
        if (thresholds or {}).get('warn_ms') == old:
            bind.execute(
                checks.update()
                .where(checks.c.id == check_id)
                .values(thresholds={**thresholds, 'warn_ms': new})
            )


def upgrade() -> None:
    _replace(2000, 30000)


def downgrade() -> None:
    _replace(30000, 2000)
