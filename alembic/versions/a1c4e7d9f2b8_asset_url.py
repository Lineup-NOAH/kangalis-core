"""assets.url — elle eklenen tekil URL varlığı (ip artık nullable)

Revision ID: a1c4e7d9f2b8
Revises: f3c9a7e1b2d8
Create Date: 2026-06-10 16:30:00.000000

Patron isteği: envantere tekil URL varlığı eklenebilsin (web/normal taramada kullanılır).
URL kimliği (şema/port/yol) korunur; bu varlıklarda ``ip`` BOŞ (NULL) olabilir. Postgres
unique indeksi çoklu NULL'a izin verdiğinden ``ip`` unique kalır ama nullable olur.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "a1c4e7d9f2b8"
down_revision: Union[str, Sequence[str], None] = "f3c9a7e1b2d8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # IP artık zorunlu değil (URL varlıklarında boş kalır).
    op.alter_column("assets", "ip", existing_type=sa.String(45), nullable=True)
    # Elle eklenen URL hedefi (benzersiz). Çoklu NULL (IP varlıkları) Postgres'te serbest.
    op.add_column("assets", sa.Column("url", sa.String(512), nullable=True))
    op.create_index("ix_assets_url", "assets", ["url"], unique=True)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_assets_url", table_name="assets")
    op.drop_column("assets", "url")
    # IP'yi tekrar NOT NULL yap (ip=NULL olan URL varlıkları varsa bu adım başarısız olabilir).
    op.alter_column("assets", "ip", existing_type=sa.String(45), nullable=False)
