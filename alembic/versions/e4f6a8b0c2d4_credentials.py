"""credentials + credential_zones (kimlik kasasi)

Revision ID: e4f6a8b0c2d4
Revises: d3e5f7a9b1c2
Create Date: 2026-06-04 22:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e4f6a8b0c2d4'
down_revision: Union[str, Sequence[str], None] = 'd3e5f7a9b1c2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'credentials',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column(
            'cred_type',
            sa.Enum('ssh', 'winrm', 'rdp', name='credentialtype', native_enum=False, length=20),
            nullable=False,
        ),
        sa.Column('username', sa.String(length=150), nullable=False),
        sa.Column('secret_encrypted', sa.Text(), nullable=False),
        sa.Column('domain', sa.String(length=150), nullable=True),
        sa.Column('port', sa.Integer(), nullable=True),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_credentials_name'), 'credentials', ['name'], unique=True)

    op.create_table(
        'credential_zones',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('credential_ids', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        op.f('ix_credential_zones_name'), 'credential_zones', ['name'], unique=True
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_credential_zones_name'), table_name='credential_zones')
    op.drop_table('credential_zones')
    op.drop_index(op.f('ix_credentials_name'), table_name='credentials')
    op.drop_table('credentials')
