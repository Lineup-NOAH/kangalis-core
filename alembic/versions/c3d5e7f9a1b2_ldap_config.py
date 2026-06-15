"""ldap config table

Revision ID: c3d5e7f9a1b2
Revises: b2c4d6e8f0a1
Create Date: 2026-06-05 13:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c3d5e7f9a1b2'
down_revision: Union[str, Sequence[str], None] = 'b2c4d6e8f0a1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'ldap_config',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('server_uri', sa.String(length=255), nullable=False),
        sa.Column('use_ssl', sa.Boolean(), nullable=False),
        sa.Column('bind_dn', sa.String(length=255), nullable=False),
        sa.Column('bind_password_encrypted', sa.Text(), nullable=True),
        sa.Column('base_dn', sa.String(length=255), nullable=False),
        sa.Column('user_filter', sa.String(length=255), nullable=False),
        sa.Column('attr_username', sa.String(length=64), nullable=False),
        sa.Column('attr_email', sa.String(length=64), nullable=False),
        sa.Column('attr_display_name', sa.String(length=64), nullable=False),
        sa.Column('default_role', sa.String(length=20), nullable=False),
        sa.Column(
            'updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False
        ),
        sa.PrimaryKeyConstraint('id'),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('ldap_config')
