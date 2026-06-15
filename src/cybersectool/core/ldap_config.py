"""LDAP bağlantı yapılandırması (DB) — kullanıcı arama/içe aktarma için.

Tek satırlık ``ldap_config`` (id=1). Bind (servis hesabı) parolası Fernet ile
şifreli saklanır; ham parola yalnızca arama/test anında çözülür.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.core.crypto import decrypt_secret, encrypt_secret
from cybersectool.core.models import LdapConfig


async def get_ldap_config(session: AsyncSession) -> LdapConfig | None:
    """Kayıtlı LDAP yapılandırmasını döndürür (yoksa None)."""
    result = await session.execute(select(LdapConfig).where(LdapConfig.id == 1))
    return result.scalar_one_or_none()


async def save_ldap_config(
    session: AsyncSession,
    *,
    server_uri: str,
    use_ssl: bool,
    bind_dn: str,
    base_dn: str,
    user_filter: str,
    attr_username: str,
    attr_email: str,
    attr_display_name: str,
    default_role: str,
    bind_password: str | None = None,
) -> LdapConfig:
    """LDAP yapılandırmasını oluşturur ya da günceller (id=1).

    bind_password verilmezse (None/boş) mevcut şifreli parola korunur — böylece
    formu parola alanı boş bırakarak diğer alanlar güncellenebilir.
    """
    config = await get_ldap_config(session)
    if config is None:
        config = LdapConfig(id=1)
        session.add(config)
    config.server_uri = server_uri.strip()
    config.use_ssl = use_ssl
    config.bind_dn = bind_dn.strip()
    config.base_dn = base_dn.strip()
    config.user_filter = user_filter.strip() or "(objectClass=person)"
    config.attr_username = attr_username.strip() or "uid"
    config.attr_email = attr_email.strip() or "mail"
    config.attr_display_name = attr_display_name.strip() or "cn"
    config.default_role = default_role
    if bind_password:
        config.bind_password_encrypted = encrypt_secret(bind_password)
    await session.commit()
    await session.refresh(config)
    return config


def get_bind_password(config: LdapConfig) -> str:
    """Şifreli bind parolasını çözer (yoksa boş dize — anonim bind)."""
    if not config.bind_password_encrypted:
        return ""
    return decrypt_secret(config.bind_password_encrypted)
