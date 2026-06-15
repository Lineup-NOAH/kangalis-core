"""compliance_checks table

Revision ID: f8b0d2e4a6c8
Revises: e7a9c1b3d5f7
Create Date: 2026-06-06 05:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f8b0d2e4a6c8'
down_revision: Union[str, Sequence[str], None] = 'e7a9c1b3d5f7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'compliance_checks',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=False),
        sa.Column('framework', sa.String(length=50), nullable=False),
        sa.Column('control_id', sa.String(length=20), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('status', sa.String(length=10), nullable=False),
        sa.Column('severity', sa.String(length=10), nullable=True),
        sa.Column('detail', sa.Text(), nullable=True),
        sa.Column(
            'created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        'ix_compliance_checks_scan_id', 'compliance_checks', ['scan_id'], unique=False
    )
    op.create_index(
        'ix_compliance_checks_framework', 'compliance_checks', ['framework'], unique=False
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_compliance_checks_framework', table_name='compliance_checks')
    op.drop_index('ix_compliance_checks_scan_id', table_name='compliance_checks')
    op.drop_table('compliance_checks')
