"""v1.4: container images are scanned when someone asks, from the host page

Additive only: one new nullable column on hosts. No data is changed or dropped.

Revision ID: 0004
Revises: 0003
"""
from alembic import op
import sqlalchemy as sa


revision = '0004'
down_revision = '0003'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('hosts') as b:
        b.add_column(sa.Column('image_scan_requests', sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('hosts') as b:
        b.drop_column('image_scan_requests')
