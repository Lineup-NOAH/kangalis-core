"""cves.category — Zafiyet DB kategori çipleri (platform/kullanım, açıklamadan)

Revision ID: c9f6d2b4a8e1
Revises: b8e5c3a1f7d4
Create Date: 2026-06-09 19:30:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "c9f6d2b4a8e1"
down_revision: Union[str, Sequence[str], None] = "b8e5c3a1f7d4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column("cves", sa.Column("category", sa.String(length=16), nullable=True))
    op.create_index("ix_cves_category", "cves", ["category"])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_cves_category", table_name="cves")
    op.drop_column("cves", "category")
