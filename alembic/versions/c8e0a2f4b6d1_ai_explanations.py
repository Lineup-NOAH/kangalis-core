"""yerel AI üretim önbelleği: ai_explanations tablosu

Aynı CVE/bulgu/özet için AI tekrar üretilmez (CPU pahalı). cache_key tekil + indeksli;
content üretilen metni, model hangi modelin ürettiğini tutar.

Revision ID: c8e0a2f4b6d1
Revises: b7d9f1a3c5e2
Create Date: 2026-06-12 09:30:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c8e0a2f4b6d1"
down_revision: Union[str, Sequence[str], None] = "b7d9f1a3c5e2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "ai_explanations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("cache_key", sa.String(length=128), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("model", sa.String(length=128), nullable=False, server_default=""),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_ai_explanations_cache_key"),
        "ai_explanations",
        ["cache_key"],
        unique=True,
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f("ix_ai_explanations_cache_key"), table_name="ai_explanations")
    op.drop_table("ai_explanations")
