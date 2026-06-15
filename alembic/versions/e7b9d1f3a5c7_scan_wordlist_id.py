"""scan.wordlist_id (dizin taramasında kullanılacak özel kelime listesi)

Revision ID: e7b9d1f3a5c7
Revises: d5f7a9c1b3e5
Create Date: 2026-06-08 11:45:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'e7b9d1f3a5c7'
down_revision: str | Sequence[str] | None = 'd5f7a9c1b3e5'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('scans', sa.Column('wordlist_id', sa.Integer(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('scans', 'wordlist_id')
