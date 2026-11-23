"""v1.8: remember which container images were scanned and when, so replacements are rescanned

Additive only: one new nullable column on hosts. No data is changed or dropped.

Revision ID: 0006
Revises: 0005
"""
from alembic import op
import sqlalchemy as sa


revision = '0006'
down_revision = '0005'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('hosts') as b:
        b.add_column(sa.Column('image_scans', sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('hosts') as b:
        b.drop_column('image_scans')
