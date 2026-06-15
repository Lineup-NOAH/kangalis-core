"""users tablosuna MFA kolonları (yöntem + şifreli sır + etkin)

Revision ID: e1a3c5d7f9b2
Revises: d0f2a4c6e8fa
Create Date: 2026-06-05 19:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e1a3c5d7f9b2'
down_revision: Union[str, Sequence[str], None] = 'd0f2a4c6e8fa'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        'users',
        sa.Column('mfa_method', sa.String(length=10), nullable=False, server_default='none'),
    )
    op.add_column('users', sa.Column('mfa_secret_encrypted', sa.Text(), nullable=True))
    op.add_column(
        'users',
        sa.Column('mfa_enabled', sa.Boolean(), nullable=False, server_default=sa.text('false')),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('users', 'mfa_enabled')
    op.drop_column('users', 'mfa_secret_encrypted')
    op.drop_column('users', 'mfa_method')
