"""app_settings timezone field (IX-1)

Revision ID: b0d2f4a6c8e0
Revises: a9c1e3f5b7d2
Create Date: 2026-06-07 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b0d2f4a6c8e0'
down_revision: Union[str, Sequence[str], None] = 'a9c1e3f5b7d2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        'app_settings',
        sa.Column(
            'timezone',
            sa.String(length=64),
            nullable=False,
            server_default='Europe/Istanbul',
        ),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('app_settings', 'timezone')
