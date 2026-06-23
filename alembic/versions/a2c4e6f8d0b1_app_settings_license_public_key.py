"""app_settings license_public_key

Doğrulama açık anahtarı (patronun Ed25519 public key'i, base64) için
``app_settings.license_public_key`` kolonu. GİZLİ DEĞİLDİR; lisans imzaları bununla
doğrulanır. Boş ise config.license_public_key (env LICENSE_PUBLIC_KEY) fallback olur →
açık anahtar artık .env'e dokunmadan UI'dan (Lisans sekmesi) girilebilir.

Revision ID: a2c4e6f8d0b1
Revises: f1e3d5c7a9b2
Create Date: 2026-06-23 14:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a2c4e6f8d0b1"
down_revision: str | Sequence[str] | None = "f1e3d5c7a9b2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "app_settings",
        sa.Column("license_public_key", sa.String(length=255), nullable=False, server_default=""),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("app_settings", "license_public_key")
