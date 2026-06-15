"""finding + vulnerability validated (NSE-confirmed)

Revision ID: c5e7f9b1d3a5
Revises: b4d6f8a0c2e4
Create Date: 2026-06-06 02:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c5e7f9b1d3a5'
down_revision: Union[str, Sequence[str], None] = 'b4d6f8a0c2e4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        'findings',
        sa.Column('validated', sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        'vulnerabilities',
        sa.Column('validated', sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('vulnerabilities', 'validated')
    op.drop_column('findings', 'validated')
