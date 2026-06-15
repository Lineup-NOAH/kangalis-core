"""nvd_sync_days varsayılanını 120 → 7'ye indir (günlük oto-senkron son 1 hafta)

Günlük ``cpe_sync`` her seferinde ``nvd_sync_days`` penceresini (eski varsayılan 120 gün
≈ 16.000 CVE) baştan çekip Postgres'e topluca yazıyordu → worker/DB'yi gereksiz CPU yükü
altına sokuyordu. Günlük tazeleme için 1 hafta yeterli; geçmiş yükleme ayrı backfill ile
yapılır. server_default 7'ye çekilir ve hâlâ ESKİ varsayılanda (120) duran satır 7'ye
düşürülür (operatörün bilinçli seçtiği farklı bir değer varsa DOKUNULMAZ).

Revision ID: d8b1f4a2c6e9
Revises: c3f8a2e6d1b9
Create Date: 2026-06-11 02:00:00.000000

"""

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d8b1f4a2c6e9"
down_revision: Union[str, Sequence[str], None] = "c3f8a2e6d1b9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.alter_column("app_settings", "nvd_sync_days", server_default="7")
    # Yalnız hâlâ eski varsayılanda (120) duran satırları düşür — bilinçli özel değeri koru.
    op.execute("UPDATE app_settings SET nvd_sync_days = 7 WHERE nvd_sync_days = 120")


def downgrade() -> None:
    """Downgrade schema."""
    op.alter_column("app_settings", "nvd_sync_days", server_default="120")
    op.execute("UPDATE app_settings SET nvd_sync_days = 120 WHERE nvd_sync_days = 7")
