"""v1.25: when each session was last used, for SESSION_IDLE_MINUTES

Additive only: one new nullable column on sessions. No data is changed or dropped.

Revision ID: 0013
Revises: 0012
"""
from alembic import op
import sqlalchemy as sa


revision = '0013'
down_revision = '0012'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('sessions') as b:
        b.add_column(sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('sessions') as b:
        b.drop_column('last_seen_at')
