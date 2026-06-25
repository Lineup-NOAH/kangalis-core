"""reverse-dns default off

``app_settings.reverse_dns_enabled`` varsayilani ON -> OFF. Yeni kurulumlar nmap ``-n``
kullanir (DNS cozumu yok -> daha hizli/sessiz; PTR'siz ya da yavas cozucu ortamlarda
taramayi bekletmez). MEVCUT satirlarin degeri DEGISMEZ (operator secimine saygi) -
yalnizca sutunun server_default'u guncellenir; isteyen Ayarlar'dan tekrar acabilir.

Revision ID: d4e6f8a0c2b1
Revises: c1f4a8e2d7b9
Create Date: 2026-06-25 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d4e6f8a0c2b1"
down_revision: str | Sequence[str] | None = "c1f4a8e2d7b9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.alter_column(
        "app_settings",
        "reverse_dns_enabled",
        existing_type=sa.Boolean(),
        server_default=sa.text("false"),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.alter_column(
        "app_settings",
        "reverse_dns_enabled",
        existing_type=sa.Boolean(),
        server_default=sa.text("true"),
    )
