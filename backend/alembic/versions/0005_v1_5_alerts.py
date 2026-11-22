"""v1.5: alerts. Records what has been alerted so each thing alerts once.

Additive only: one new table. No data is changed or dropped.

Revision ID: 0005
Revises: 0004
"""
from alembic import op
import sqlalchemy as sa


revision = '0005'
down_revision = '0004'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'alerts_sent',
        sa.Column('key', sa.String(200), primary_key=True),
        sa.Column('sent_at', sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table('alerts_sent')
