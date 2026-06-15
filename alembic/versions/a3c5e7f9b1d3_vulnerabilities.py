"""vulnerabilities

Revision ID: a3c5e7f9b1d3
Revises: f2b4d6e8a0c1
Create Date: 2026-06-06 01:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a3c5e7f9b1d3'
down_revision: Union[str, Sequence[str], None] = 'f2b4d6e8a0c1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'vulnerabilities',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('asset_id', sa.Integer(), nullable=False),
        sa.Column('fingerprint', sa.String(length=255), nullable=False),
        sa.Column(
            'scan_type',
            sa.Enum(
                'network', 'vuln', 'web', 'sca', 'hardening', 'credentialed',
                name='scantype', native_enum=False, length=20,
            ),
            nullable=False,
        ),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column(
            'severity',
            sa.Enum(
                'critical', 'high', 'medium', 'low', 'info',
                name='severity', native_enum=False, length=10,
            ),
            nullable=False,
        ),
        sa.Column('cve_id', sa.String(length=30), nullable=True),
        sa.Column('risk_score', sa.Float(), nullable=True),
        sa.Column(
            'status',
            sa.Enum(
                'open', 'confirmed', 'resolved', 'false_positive', 'accepted_risk',
                name='findingstatus', native_enum=False, length=20,
            ),
            nullable=False,
        ),
        sa.Column(
            'first_seen', sa.DateTime(timezone=True), server_default=sa.text('now()'),
            nullable=False,
        ),
        sa.Column(
            'last_seen', sa.DateTime(timezone=True), server_default=sa.text('now()'),
            nullable=False,
        ),
        sa.Column('last_scan_id', sa.Integer(), nullable=True),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('reopened_count', sa.Integer(), server_default='0', nullable=False),
        sa.Column('coverage', sa.Integer(), server_default='1', nullable=False),
        sa.Column('note', sa.Text(), nullable=True),
        sa.Column('updated_by', sa.Integer(), nullable=True),
        sa.Column(
            'created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['last_scan_id'], ['scans.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['updated_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('asset_id', 'fingerprint', name='uq_vuln_asset_fp'),
    )
    op.create_index('ix_vulnerabilities_asset_id', 'vulnerabilities', ['asset_id'])
    op.create_index('ix_vulnerabilities_fingerprint', 'vulnerabilities', ['fingerprint'])
    op.create_index('ix_vulnerabilities_cve_id', 'vulnerabilities', ['cve_id'])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_vulnerabilities_cve_id', table_name='vulnerabilities')
    op.drop_index('ix_vulnerabilities_fingerprint', table_name='vulnerabilities')
    op.drop_index('ix_vulnerabilities_asset_id', table_name='vulnerabilities')
    op.drop_table('vulnerabilities')
