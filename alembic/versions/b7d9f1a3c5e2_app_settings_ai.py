"""app_settings'e yerel AI (Ollama) ayarları ekle: ai_enabled + endpoint + model + timeout

Kangalis on-prem AI asistanı (zafiyet açıklama + rapor özeti) admin UI'dan açılır/yönetilir.
Boş endpoint/model → config.py env varsayılanına düşer; ai_enabled KAPALI iken AI devre dışı.

Revision ID: b7d9f1a3c5e2
Revises: f1a9c3d7e2b5
Create Date: 2026-06-12 09:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b7d9f1a3c5e2"
down_revision: Union[str, Sequence[str], None] = "f1a9c3d7e2b5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "app_settings",
        sa.Column("ai_enabled", sa.Boolean(), nullable=False, server_default="false"),
    )
    op.add_column(
        "app_settings",
        sa.Column("ai_endpoint_url", sa.String(length=255), nullable=False, server_default=""),
    )
    op.add_column(
        "app_settings",
        sa.Column("ai_model_name", sa.String(length=128), nullable=False, server_default=""),
    )
    op.add_column(
        "app_settings",
        sa.Column("ai_timeout_sec", sa.Integer(), nullable=False, server_default="60"),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("app_settings", "ai_timeout_sec")
    op.drop_column("app_settings", "ai_model_name")
    op.drop_column("app_settings", "ai_endpoint_url")
    op.drop_column("app_settings", "ai_enabled")
