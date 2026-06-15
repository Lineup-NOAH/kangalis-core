"""scan batches + scan progress

Revision ID: f6a8b0c2d4e6
Revises: e5f7a9b1c3d4
Create Date: 2026-06-05 15:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f6a8b0c2d4e6'
down_revision: Union[str, Sequence[str], None] = 'e5f7a9b1c3d4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'scan_batches',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=150), nullable=False),
        sa.Column(
            'mode',
            sa.Enum('safe', 'aggressive', name='scanmode', native_enum=False, length=20),
            nullable=False,
        ),
        sa.Column('categories', sa.JSON(), nullable=True),
        sa.Column('created_by', sa.Integer(), nullable=True),
        sa.Column(
            'created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False
        ),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.add_column('scans', sa.Column('batch_id', sa.Integer(), nullable=True))
    op.create_index('ix_scans_batch_id', 'scans', ['batch_id'])
    op.create_foreign_key(
        'fk_scans_batch_id', 'scans', 'scan_batches', ['batch_id'], ['id'], ondelete='CASCADE'
    )
    op.add_column(
        'scans', sa.Column('progress', sa.Integer(), nullable=False, server_default='0')
    )
    op.add_column('scans', sa.Column('phase', sa.String(length=120), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('scans', 'phase')
    op.drop_column('scans', 'progress')
    op.drop_constraint('fk_scans_batch_id', 'scans', type_='foreignkey')
    op.drop_index('ix_scans_batch_id', table_name='scans')
    op.drop_column('scans', 'batch_id')
    op.drop_table('scan_batches')
