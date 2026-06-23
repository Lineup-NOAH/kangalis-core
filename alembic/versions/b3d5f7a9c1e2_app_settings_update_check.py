"""app_settings update check fields

Güncelleme denetimi alanları: ``update_check_enabled`` (egress aç/kapa — air-gap için
kapatılabilir), ``update_check_url`` (sürüm kaynağı, GitHub Releases; kendi ayna için
değiştirilebilir), ``latest_version`` + ``update_last_checked`` + ``update_last_status``
(son denetim sonucu — /update sayfası gösterir). Yalnız bu denetim internete çıkar.

Revision ID: b3d5f7a9c1e2
Revises: a2c4e6f8d0b1
Create Date: 2026-06-24 12:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b3d5f7a9c1e2"
down_revision: str | Sequence[str] | None = "a2c4e6f8d0b1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_DEFAULT_URL = "https://api.github.com/repos/Lineup-NOAH/kangalis-core/releases/latest"


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "app_settings",
        sa.Column(
            "update_check_enabled", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
    )
    op.add_column(
        "app_settings",
        sa.Column(
            "update_check_url", sa.String(length=500), nullable=False, server_default=_DEFAULT_URL
        ),
    )
    op.add_column(
        "app_settings",
        sa.Column("latest_version", sa.String(length=64), nullable=False, server_default=""),
    )
    op.add_column(
        "app_settings",
        sa.Column("update_last_checked", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "app_settings",
        sa.Column("update_last_status", sa.String(length=16), nullable=False, server_default=""),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("app_settings", "update_last_status")
    op.drop_column("app_settings", "update_last_checked")
    op.drop_column("app_settings", "latest_version")
    op.drop_column("app_settings", "update_check_url")
    op.drop_column("app_settings", "update_check_enabled")
