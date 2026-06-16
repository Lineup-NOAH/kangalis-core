"""app_settings.ai_timeout_sec varsayılanını 60 → 300'e yükselt (#273)

Grounded rapor üretimi (özet/script/asset-story) CPU'da qwen3:8b ile sıcak modelde bile ~3-5 dk
sürer; 60 sn varsayılan ağır AI yüzeylerini timeout'a düşürüyordu. config.ai_timeout,
normalize_ai_timeout ve dokümanlar zaten 300 diyordu — efektif kolon/server_default varsayılanı
da 300'e hizalanır. server_default 300'e çekilir ve hâlâ ESKİ varsayılanda (60) duran satır 300'e
yükseltilir (operatörün bilinçli seçtiği farklı bir değer varsa DOKUNULMAZ).

Revision ID: e3b7d1f9a2c4
Revises: c8e0a2f4b6d1
Create Date: 2026-06-16 12:00:00.000000

"""

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e3b7d1f9a2c4"
down_revision: Union[str, Sequence[str], None] = "c8e0a2f4b6d1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.alter_column("app_settings", "ai_timeout_sec", server_default="300")
    # Yalnız hâlâ eski varsayılanda (60) duran satırları yükselt — bilinçli özel değeri koru.
    op.execute("UPDATE app_settings SET ai_timeout_sec = 300 WHERE ai_timeout_sec = 60")


def downgrade() -> None:
    """Downgrade schema."""
    op.alter_column("app_settings", "ai_timeout_sec", server_default="60")
    op.execute("UPDATE app_settings SET ai_timeout_sec = 60 WHERE ai_timeout_sec = 300")
