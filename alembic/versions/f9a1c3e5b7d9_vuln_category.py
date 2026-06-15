"""vulnerability.category (Zafiyetler sayfası kategori filtresi/rozeti)

Revision ID: f9a1c3e5b7d9
Revises: e7b9d1f3a5c7
Create Date: 2026-06-08 12:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f9a1c3e5b7d9'
down_revision: Union[str, Sequence[str], None] = 'e7b9d1f3a5c7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema + mevcut satırları kategoriye göre doldur (derive_vuln_category ile aynı kural)."""
    op.add_column('vulnerabilities', sa.Column('category', sa.String(length=20), nullable=True))
    op.create_index(op.f('ix_vulnerabilities_category'), 'vulnerabilities', ['category'])
    # Backfill (öncelik sırası önemli — weak_credential override EN SONA yazılır).
    op.execute("UPDATE vulnerabilities SET category = 'cve' WHERE cve_id IS NOT NULL")
    op.execute(
        "UPDATE vulnerabilities SET category = 'web' "
        "WHERE category IS NULL AND scan_type = 'web'"
    )
    op.execute(
        "UPDATE vulnerabilities SET category = 'sca' "
        "WHERE category IS NULL AND scan_type = 'sca'"
    )
    op.execute(
        "UPDATE vulnerabilities SET category = 'config' "
        "WHERE category IS NULL AND scan_type IN ('credentialed', 'hardening')"
    )
    op.execute("UPDATE vulnerabilities SET category = 'other' WHERE category IS NULL")
    # weak_credential başlık önekleri (derive_vuln_category ile aynı) — en yüksek öncelik.
    op.execute(
        "UPDATE vulnerabilities SET category = 'weak_credential' "
        "WHERE lower(title) LIKE 'zayıf/varsayılan kimlik bulundu%' "
        "OR lower(title) LIKE 'varsayılan ssh kimliği%' "
        "OR lower(title) LIKE 'varsayılan kimlik%'"
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_vulnerabilities_category'), table_name='vulnerabilities')
    op.drop_column('vulnerabilities', 'category')
