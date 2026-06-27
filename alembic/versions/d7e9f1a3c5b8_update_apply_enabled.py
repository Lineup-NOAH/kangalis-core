"""app_settings.update_apply_enabled (uygulama-ici otomatik guncelleme opt-in)

Uygulama-ici OTOMATIK guncelleme (docker.sock ile host yiginini yeniden derle+baslat)
icin opt-in bayragi. VARSAYILAN KAPALI (false) — operator /update sayfasindan acar.
Mevcut satirlar da kapali baslar (guvenli varsayilan).

Revision ID: d7e9f1a3c5b8
Revises: d4e6f8a0c2b1
Create Date: 2026-06-27 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d7e9f1a3c5b8"
down_revision: str | Sequence[str] | None = "d4e6f8a0c2b1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "app_settings",
        sa.Column(
            "update_apply_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("app_settings", "update_apply_enabled")
