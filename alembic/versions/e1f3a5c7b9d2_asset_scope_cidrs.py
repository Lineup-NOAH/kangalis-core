"""app_settings varlık kapsamı (asset_scope_cidrs) — yalnız iç IP'ler varlık (F1)

Revision ID: e1f3a5c7b9d2
Revises: f9a1c3e5b7d9
Create Date: 2026-06-09 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e1f3a5c7b9d2'
down_revision: Union[str, Sequence[str], None] = 'f9a1c3e5b7d9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Varsayılan varlık kapsamı: RFC1918 (özel) + loopback (IPv4/IPv6 ULA/link-local).
_DEFAULT = (
    '["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", '
    '"::1/128", "fc00::/7", "fe80::/10"]'
)


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        'app_settings',
        sa.Column('asset_scope_cidrs', sa.JSON(), nullable=False, server_default=_DEFAULT),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('app_settings', 'asset_scope_cidrs')
