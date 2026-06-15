"""asset is_up (tarama/ping ile ayakta dogrulandi)

Revision ID: a9c1e3f5b7d2
Revises: f8b0d2e4a6c8
Create Date: 2026-06-06 13:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a9c1e3f5b7d2"
down_revision: str | Sequence[str] | None = "f8b0d2e4a6c8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "assets",
        sa.Column("is_up", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("assets", "is_up")
