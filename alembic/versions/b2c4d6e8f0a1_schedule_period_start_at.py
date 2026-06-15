"""schedule period + start_at

Revision ID: b2c4d6e8f0a1
Revises: 1a700bb42ab9
Create Date: 2026-06-05 13:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b2c4d6e8f0a1'
down_revision: Union[str, Sequence[str], None] = '1a700bb42ab9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # period: mevcut satırlar 'interval' (interval_minutes ile eski davranış korunur).
    op.add_column(
        'scheduled_scans',
        sa.Column('period', sa.String(length=20), nullable=False, server_default='interval'),
    )
    op.add_column(
        'scheduled_scans',
        sa.Column('start_at', sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('scheduled_scans', 'start_at')
    op.drop_column('scheduled_scans', 'period')
