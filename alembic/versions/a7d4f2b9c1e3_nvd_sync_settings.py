"""app_settings NVD senkron ayarları (nvd_sync_days + nvd_api_key_encrypted)

Revision ID: a7d4f2b9c1e3
Revises: c9e1a3b5d7f2
Create Date: 2026-06-09 16:00:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "a7d4f2b9c1e3"
down_revision: Union[str, Sequence[str], None] = "c9e1a3b5d7f2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "app_settings",
        sa.Column("nvd_sync_days", sa.Integer(), nullable=False, server_default="120"),
    )
    op.add_column(
        "app_settings",
        sa.Column("nvd_api_key_encrypted", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("app_settings", "nvd_api_key_encrypted")
    op.drop_column("app_settings", "nvd_sync_days")
