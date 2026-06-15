"""scan mode (safe/aggressive)

Revision ID: a7f3c2e9d014
Revises: af93c05a857c
Create Date: 2026-06-04 21:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a7f3c2e9d014'
down_revision: Union[str, Sequence[str], None] = 'af93c05a857c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Mevcut satırlar için güvenli varsayılan ('safe'), sonra server_default kaldırılır.
    op.add_column(
        'scans',
        sa.Column(
            'mode',
            sa.Enum('safe', 'aggressive', name='scanmode', native_enum=False, length=20),
            nullable=False,
            server_default='safe',
        ),
    )
    op.alter_column('scans', 'mode', server_default=None)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('scans', 'mode')
