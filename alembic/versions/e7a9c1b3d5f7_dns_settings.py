"""app_settings DNS / reverse-DNS fields

Revision ID: e7a9c1b3d5f7
Revises: d6f8a0c2e4b6
Create Date: 2026-06-06 04:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e7a9c1b3d5f7'
down_revision: Union[str, Sequence[str], None] = 'd6f8a0c2e4b6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        'app_settings',
        sa.Column('dns_servers', sa.String(length=255), nullable=False, server_default=''),
    )
    op.add_column(
        'app_settings',
        sa.Column(
            'reverse_dns_enabled', sa.Boolean(), nullable=False, server_default=sa.true()
        ),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('app_settings', 'reverse_dns_enabled')
    op.drop_column('app_settings', 'dns_servers')
