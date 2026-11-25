"""v1.19: whether each component is running (from the agent), so findings in idle software rank lower

Additive only: one new nullable column on components. No data is changed or dropped. Findings in installed
kernels that aren't booted are set aside as 'not_booted' by the next match, not by this migration.

Revision ID: 0011
Revises: 0010
"""
from alembic import op
import sqlalchemy as sa


revision = '0011'
down_revision = '0010'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('components') as b:
        b.add_column(sa.Column('in_use', sa.Boolean(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('components') as b:
        b.drop_column('in_use')
