"""scans.include_udp — UDP servis taraması (-sU) opsiyonu (#143)

Revision ID: e2b8f1d4a6c7
Revises: d1a7e4f9c2b6
Create Date: 2026-06-10 04:00:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "e2b8f1d4a6c7"
down_revision: Union[str, Sequence[str], None] = "d1a7e4f9c2b6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "scans",
        sa.Column("include_udp", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("scans", "include_udp")
