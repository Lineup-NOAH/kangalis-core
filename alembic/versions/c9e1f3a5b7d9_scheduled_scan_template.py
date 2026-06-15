"""scheduled scan batch template (çoklu hedef + kimlik + mod + kategori)

Revision ID: c9e1f3a5b7d9
Revises: b8d0f2a4c6e8
Create Date: 2026-06-05 17:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c9e1f3a5b7d9'
down_revision: Union[str, Sequence[str], None] = 'b8d0f2a4c6e8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        'scheduled_scans',
        sa.Column('name', sa.String(length=150), nullable=False, server_default=''),
    )
    op.add_column(
        'scheduled_scans',
        sa.Column('zone_ids', sa.JSON(), nullable=False, server_default='[]'),
    )
    op.add_column(
        'scheduled_scans',
        sa.Column('asset_ids', sa.JSON(), nullable=False, server_default='[]'),
    )
    op.add_column(
        'scheduled_scans',
        sa.Column('credential_zone_ids', sa.JSON(), nullable=False, server_default='[]'),
    )
    op.add_column(
        'scheduled_scans',
        sa.Column('credential_ids', sa.JSON(), nullable=False, server_default='[]'),
    )
    op.add_column(
        'scheduled_scans',
        sa.Column('mode', sa.String(length=20), nullable=False, server_default='safe'),
    )
    op.add_column(
        'scheduled_scans',
        sa.Column('categories', sa.JSON(), nullable=False, server_default='[]'),
    )
    op.add_column(
        'scheduled_scans',
        sa.Column('created_by', sa.Integer(), nullable=True),
    )
    op.create_foreign_key(
        'fk_scheduled_scans_created_by',
        'scheduled_scans',
        'users',
        ['created_by'],
        ['id'],
        ondelete='SET NULL',
    )
    # Eski tekil-hedef satırların target'i NULL olamaz → boş default ekle (geriye uyum).
    op.alter_column(
        'scheduled_scans',
        'target',
        existing_type=sa.String(length=255),
        server_default='',
        existing_nullable=False,
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_constraint('fk_scheduled_scans_created_by', 'scheduled_scans', type_='foreignkey')
    op.drop_column('scheduled_scans', 'created_by')
    op.drop_column('scheduled_scans', 'categories')
    op.drop_column('scheduled_scans', 'mode')
    op.drop_column('scheduled_scans', 'credential_ids')
    op.drop_column('scheduled_scans', 'credential_zone_ids')
    op.drop_column('scheduled_scans', 'asset_ids')
    op.drop_column('scheduled_scans', 'zone_ids')
    op.drop_column('scheduled_scans', 'name')
