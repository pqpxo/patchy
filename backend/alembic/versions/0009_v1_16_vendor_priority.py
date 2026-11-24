"""v1.16: the distro's own rating of each finding (Debian urgency, Ubuntu priority)

Additive only: one new nullable column on findings. No data is changed or dropped. Findings that Debian
or Ubuntu rate unimportant are set aside as 'minor' by the next match, not by this migration.

Revision ID: 0009
Revises: 0008
"""
from alembic import op
import sqlalchemy as sa


revision = '0009'
down_revision = '0008'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('findings') as b:
        b.add_column(sa.Column('vendor_priority', sa.String(32), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('findings') as b:
        b.drop_column('vendor_priority')
