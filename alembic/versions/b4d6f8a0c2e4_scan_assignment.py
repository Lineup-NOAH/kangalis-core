"""scan assignment (atama + tamamlanma bildirimi + ops. PDF rapor)

Revision ID: b4d6f8a0c2e4
Revises: a3c5e7f9b1d3
Create Date: 2026-06-06 09:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b4d6f8a0c2e4'
down_revision: Union[str, Sequence[str], None] = 'a3c5e7f9b1d3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # scans: atanan kullanıcı + bildirim/ek bayrakları
    op.add_column('scans', sa.Column('assigned_user_id', sa.Integer(), nullable=True))
    op.add_column(
        'scans',
        sa.Column(
            'notify_on_complete',
            sa.Boolean(),
            server_default=sa.text('false'),
            nullable=False,
        ),
    )
    op.add_column(
        'scans',
        sa.Column(
            'attach_report',
            sa.Boolean(),
            server_default=sa.text('false'),
            nullable=False,
        ),
    )
    op.create_foreign_key(
        'fk_scans_assigned_user',
        'scans',
        'users',
        ['assigned_user_id'],
        ['id'],
        ondelete='SET NULL',
    )

    # scan_batches: aynı 3 alan + bir-kez bildirim muhafızı (notified_at)
    op.add_column('scan_batches', sa.Column('assigned_user_id', sa.Integer(), nullable=True))
    op.add_column(
        'scan_batches',
        sa.Column(
            'notify_on_complete',
            sa.Boolean(),
            server_default=sa.text('false'),
            nullable=False,
        ),
    )
    op.add_column(
        'scan_batches',
        sa.Column(
            'attach_report',
            sa.Boolean(),
            server_default=sa.text('false'),
            nullable=False,
        ),
    )
    op.add_column(
        'scan_batches',
        sa.Column('notified_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_foreign_key(
        'fk_scan_batches_assigned_user',
        'scan_batches',
        'users',
        ['assigned_user_id'],
        ['id'],
        ondelete='SET NULL',
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_constraint('fk_scan_batches_assigned_user', 'scan_batches', type_='foreignkey')
    op.drop_column('scan_batches', 'notified_at')
    op.drop_column('scan_batches', 'attach_report')
    op.drop_column('scan_batches', 'notify_on_complete')
    op.drop_column('scan_batches', 'assigned_user_id')

    op.drop_constraint('fk_scans_assigned_user', 'scans', type_='foreignkey')
    op.drop_column('scans', 'attach_report')
    op.drop_column('scans', 'notify_on_complete')
    op.drop_column('scans', 'assigned_user_id')
