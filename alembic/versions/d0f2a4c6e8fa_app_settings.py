"""app_settings tek satırlık güvenlik/operasyon ayarları tablosu

Revision ID: d0f2a4c6e8fa
Revises: c9e1f3a5b7d9
Create Date: 2026-06-05 18:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd0f2a4c6e8fa'
down_revision: Union[str, Sequence[str], None] = 'c9e1f3a5b7d9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'app_settings',
        sa.Column('id', sa.Integer(), nullable=False),
        # Giriş kaba-kuvvet koruması
        sa.Column('ratelimit_enabled', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('ratelimit_max_attempts', sa.Integer(), nullable=False, server_default='5'),
        sa.Column('ratelimit_window_sec', sa.Integer(), nullable=False, server_default='300'),
        sa.Column('ratelimit_lockout_sec', sa.Integer(), nullable=False, server_default='900'),
        # SMTP / e-posta uyarıları
        sa.Column('smtp_enabled', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('smtp_host', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('smtp_port', sa.Integer(), nullable=False, server_default='587'),
        sa.Column('smtp_username', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('smtp_password_encrypted', sa.Text(), nullable=True),
        sa.Column('smtp_from', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('smtp_use_tls', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('alert_email_to', sa.String(length=255), nullable=False, server_default=''),
        # Syslog / SIEM forward
        sa.Column('syslog_enabled', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('syslog_host', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('syslog_port', sa.Integer(), nullable=False, server_default='514'),
        sa.Column('syslog_protocol', sa.String(length=8), nullable=False, server_default='udp'),
        sa.Column('syslog_format', sa.String(length=16), nullable=False, server_default='rfc5424'),
        # Oturum / parola / LDAPS sertleştirme
        sa.Column('session_timeout_min', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('password_min_length', sa.Integer(), nullable=False, server_default='8'),
        sa.Column('password_require_complexity', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('ldaps_verify_cert', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('ldaps_ca_cert', sa.Text(), nullable=True),
        # MFA org düzeyi anahtar
        sa.Column('mfa_required', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column(
            'updated_at',
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint('id'),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('app_settings')
