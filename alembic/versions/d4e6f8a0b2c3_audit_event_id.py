"""audit log event_id

Revision ID: d4e6f8a0b2c3
Revises: c3d5e7f9a1b2
Create Date: 2026-06-05 13:50:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd4e6f8a0b2c3'
down_revision: Union[str, Sequence[str], None] = 'c3d5e7f9a1b2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        'audit_logs',
        sa.Column('event_id', sa.Integer(), nullable=False, server_default='0'),
    )
    op.create_index('ix_audit_logs_event_id', 'audit_logs', ['event_id'])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_audit_logs_event_id', table_name='audit_logs')
    op.drop_column('audit_logs', 'event_id')
