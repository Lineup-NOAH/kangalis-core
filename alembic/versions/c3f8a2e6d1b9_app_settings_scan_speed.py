"""app_settings.scan_speed — tarama hızı (nmap paralellik)

Revision ID: c3f8a2e6d1b9
Revises: a1c4e7d9f2b8
Create Date: 2026-06-11 09:00:00.000000

nmap AĞ-bound olduğundan tarama hızı RAM değil PARALELLİK ile artar. Bu ayar
(normal | fast | insane) nmap --min-hostgroup/--min-parallelism/--min-rate
bayraklarını belirler. Varsayılan ``fast`` (boştaki CPU/ağ kaynağını çok-hostlu
taramalarda kullanır, doğruluğu büyük ölçüde korur).
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "c3f8a2e6d1b9"
down_revision: Union[str, Sequence[str], None] = "a1c4e7d9f2b8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "app_settings",
        sa.Column("scan_speed", sa.String(16), nullable=False, server_default="fast"),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("app_settings", "scan_speed")
