"""app_settings'e worker dağıtımı (fan-out) ayarları ekle: scan_fanout + fanout_workers

PORT-FANOUT/CIDR-fanout açma-kapaması artık env (config.scan_fanout) yerine UI'dan (DB)
kontrol edilir; ``fanout_workers`` tek-host büyük-port taramasının kaç port-bloğuna
bölüneceğini belirler (1=bölme yok). Tarama hızından bağımsız (operatör kontrolü).

Revision ID: e7c2f9a4b1d3
Revises: d8b1f4a2c6e9
Create Date: 2026-06-11 15:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e7c2f9a4b1d3"
down_revision: Union[str, Sequence[str], None] = "d8b1f4a2c6e9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "app_settings",
        sa.Column("scan_fanout", sa.Boolean(), nullable=False, server_default="true"),
    )
    op.add_column(
        "app_settings",
        sa.Column("fanout_workers", sa.Integer(), nullable=False, server_default="8"),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("app_settings", "fanout_workers")
    op.drop_column("app_settings", "scan_fanout")
