"""v1.1: EPSS, end-of-life, NVD CPE override, Dependabot cross-check, UI settings

Additive only: new nullable columns and one new table. No data is changed or dropped.

Revision ID: 0002
Revises: 0001
"""
from alembic import op
import sqlalchemy as sa


revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('app_settings',
                    sa.Column('key', sa.String(length=64), nullable=False),
                    sa.Column('value', sa.JSON(), nullable=False),
                    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
                    sa.PrimaryKeyConstraint('key'))
    with op.batch_alter_table('advisories') as b:
        b.add_column(sa.Column('epss', sa.Float(), nullable=True))
        b.add_column(sa.Column('epss_percentile', sa.Float(), nullable=True))
    with op.batch_alter_table('components') as b:
        b.add_column(sa.Column('cpe', sa.String(length=200), nullable=True))
        b.add_column(sa.Column('eol_state', sa.String(length=16), nullable=True))
        b.add_column(sa.Column('eol', sa.JSON(), nullable=True))
        b.create_index('ix_components_eol_state', ['eol_state'], unique=False)
    with op.batch_alter_table('hosts') as b:
        b.add_column(sa.Column('os_eol_state', sa.String(length=16), nullable=True))
        b.add_column(sa.Column('os_eol', sa.JSON(), nullable=True))
    with op.batch_alter_table('repositories') as b:
        b.add_column(sa.Column('dependabot', sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('repositories') as b:
        b.drop_column('dependabot')
    with op.batch_alter_table('hosts') as b:
        b.drop_column('os_eol')
        b.drop_column('os_eol_state')
    with op.batch_alter_table('components') as b:
        b.drop_index('ix_components_eol_state')
        b.drop_column('eol')
        b.drop_column('eol_state')
        b.drop_column('cpe')
    with op.batch_alter_table('advisories') as b:
        b.drop_column('epss_percentile')
        b.drop_column('epss')
    op.drop_table('app_settings')
