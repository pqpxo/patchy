"""v1.2: Docker containers, added software and on-request rescans for hosts

Additive only: three new nullable columns on hosts. No data is changed or dropped.

Revision ID: 0003
Revises: 0002
"""
from alembic import op
import sqlalchemy as sa


revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('hosts') as b:
        b.add_column(sa.Column('containers', sa.JSON(), nullable=True))
        b.add_column(sa.Column('apps', sa.JSON(), nullable=True))
        b.add_column(sa.Column('rescan_requested_at', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('hosts') as b:
        b.drop_column('rescan_requested_at')
        b.drop_column('apps')
        b.drop_column('containers')
