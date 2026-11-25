"""v1.23: pending apt updates per host, and upgrades run from the host page

Additive only: one new nullable column on hosts and one new table. No data is changed or dropped.

Revision ID: 0012
Revises: 0011
"""
from alembic import op
import sqlalchemy as sa


revision = '0012'
down_revision = '0011'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('hosts') as b:
        b.add_column(sa.Column('updates', sa.JSON(), nullable=True))
    op.create_table(
        'upgrade_runs',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('host_id', sa.Integer(), sa.ForeignKey('hosts.id', ondelete='CASCADE'), nullable=False),
        sa.Column('status', sa.String(16), nullable=False),
        sa.Column('requested_by', sa.String(64), nullable=False),
        sa.Column('requested_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('sent_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('exit_code', sa.Integer(), nullable=True),
        sa.Column('output', sa.Text(), nullable=True),
        sa.Column('note', sa.String(255), nullable=True),
    )
    with op.batch_alter_table('upgrade_runs') as b:
        b.create_index(b.f('ix_upgrade_runs_host_id'), ['host_id'], unique=False)


def downgrade() -> None:
    op.drop_table('upgrade_runs')
    with op.batch_alter_table('hosts') as b:
        b.drop_column('updates')
