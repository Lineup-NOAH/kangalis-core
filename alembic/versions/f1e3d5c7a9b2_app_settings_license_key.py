"""app_settings license_key

Ticari lisans kodu (çevrimdışı, imza-temelli) için ``app_settings.license_key`` kolonu.
Patronun ürettiği lisans kodu uzun olabilir (base64url(payload).base64url(sig)) → String(2048).
core/licensing.py açık anahtarla imzayı doğrular → ``exploit`` özelliğini açar.

Revision ID: f1e3d5c7a9b2
Revises: e3b7d1f9a2c4
Create Date: 2026-06-23 12:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f1e3d5c7a9b2"
down_revision: str | Sequence[str] | None = "e3b7d1f9a2c4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "app_settings",
        sa.Column("license_key", sa.String(length=2048), nullable=False, server_default=""),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("app_settings", "license_key")
