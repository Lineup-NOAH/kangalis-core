"""app_settings CVE/CPE bilgi bankası tazeliği (cve_last_sync)

Revision ID: b8e5c3a1f7d4
Revises: a7d4f2b9c1e3
Create Date: 2026-06-09 19:00:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "b8e5c3a1f7d4"
down_revision: Union[str, Sequence[str], None] = "a7d4f2b9c1e3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "app_settings",
        sa.Column("cve_last_sync", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("app_settings", "cve_last_sync")
