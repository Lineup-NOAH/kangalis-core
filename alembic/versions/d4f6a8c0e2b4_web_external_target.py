"""scans dış web hedefi izni + başarısızlık sebebi (web external target)

Revision ID: d4f6a8c0e2b4
Revises: c1d3e5f7a9b0
Create Date: 2026-06-08 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd4f6a8c0e2b4'
down_revision: Union[str, Sequence[str], None] = 'c1d3e5f7a9b0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        'scans',
        sa.Column('allow_external', sa.Boolean(), nullable=False, server_default='false'),
    )
    op.add_column(
        'scans',
        sa.Column('error_reason', sa.String(length=255), nullable=True),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('scans', 'error_reason')
    op.drop_column('scans', 'allow_external')
