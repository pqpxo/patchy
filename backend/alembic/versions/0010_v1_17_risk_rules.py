"""v1.17: accepted-risk rules with an expiry date

Additive only: one new table. No data is changed or dropped.

Revision ID: 0010
Revises: 0009
"""
from alembic import op
import sqlalchemy as sa


revision = '0010'
down_revision = '0009'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'risk_rules',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('advisory', sa.String(128), nullable=True),
        sa.Column('package', sa.String(300), nullable=True),
        sa.Column('host_id', sa.Integer(), sa.ForeignKey('hosts.id', ondelete='CASCADE'), nullable=True),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_by', sa.String(64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table('risk_rules')
