"""app_settings LDAP periyodik senkron alanları (X-6)

Revision ID: c1d3e5f7a9b0
Revises: b0d2f4a6c8e0
Create Date: 2026-06-08 09:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c1d3e5f7a9b0'
down_revision: Union[str, Sequence[str], None] = 'b0d2f4a6c8e0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        'app_settings',
        sa.Column('ldap_sync_enabled', sa.Boolean(), nullable=False, server_default='false'),
    )
    op.add_column(
        'app_settings',
        sa.Column('ldap_sync_period', sa.String(length=10), nullable=False, server_default='daily'),
    )
    op.add_column(
        'app_settings',
        sa.Column('ldap_sync_hour', sa.Integer(), nullable=False, server_default='3'),
    )
    op.add_column(
        'app_settings',
        sa.Column('ldap_sync_last', sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('app_settings', 'ldap_sync_last')
    op.drop_column('app_settings', 'ldap_sync_hour')
    op.drop_column('app_settings', 'ldap_sync_period')
    op.drop_column('app_settings', 'ldap_sync_enabled')
