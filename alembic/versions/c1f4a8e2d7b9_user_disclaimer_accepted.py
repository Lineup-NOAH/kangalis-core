"""user disclaimer accepted

Sorumluluk reddi (DISCLAIMER.md) kabul zaman damgasi: ``users.disclaimer_accepted_at``
(NULL = henuz kabul etmedi -> tarama kapali). Uygulama-ici onay ekrani bunu doldurur ve
her operatorun kabulu zaman-damgali denetim kaydi olur (audit ``disclaimer_accepted``).

Revision ID: c1f4a8e2d7b9
Revises: b3d5f7a9c1e2
Create Date: 2026-06-25 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c1f4a8e2d7b9"
down_revision: str | Sequence[str] | None = "b3d5f7a9c1e2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "users",
        sa.Column("disclaimer_accepted_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("users", "disclaimer_accepted_at")
