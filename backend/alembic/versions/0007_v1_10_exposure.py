"""v1.10: network exposure per component, used to rank findings

Additive only: two new nullable columns on components. No data is changed or dropped.

Revision ID: 0007
Revises: 0006
"""
from alembic import op
import sqlalchemy as sa


revision = '0007'
down_revision = '0006'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('components') as b:
        b.add_column(sa.Column('exposure', sa.String(16), nullable=True))
        b.add_column(sa.Column('exposure_note', sa.String(200), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('components') as b:
        b.drop_column('exposure_note')
        b.drop_column('exposure')
