"""Kullanıcı servis fonksiyonları (core katmanı)."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.config import settings
from cybersectool.core.app_settings import get_settings
from cybersectool.core.crypto import decrypt_secret, encrypt_secret
from cybersectool.core.ldap import ldap_authenticate
from cybersectool.core.mfa import generate_totp_secret, verify_totp
from cybersectool.core.models import AuthSource, Role, User
from cybersectool.core.security import hash_password, verify_password


async def get_user_by_username(session: AsyncSession, username: str) -> User | None:
    result = await session.execute(select(User).where(User.username == username))
    return result.scalar_one_or_none()


async def get_user_by_id(session: AsyncSession, user_id: int) -> User | None:
    return await session.get(User, user_id)


async def list_users(session: AsyncSession) -> list[User]:
    result = await session.execute(select(User).order_by(User.id))
    return list(result.scalars().all())


async def create_user(
    session: AsyncSession,
    username: str,
    password: str,
    *,
    role: Role = Role.viewer,
    email: str | None = None,
) -> User:
    # Boş / yalnız-boşluk kullanıcı adı engellenir: login formu (required) bu hesaba ASLA
    # erişemez -> "hayalet" admin = kilitlenme (kurulum sihirbazında ad boş bırakılınca yaşandı).
    # Tek yerde (servis katmanı) engelle ki CLI/UI/sihirbaz hangi yoldan gelirse gelsin korunsun.
    username = username.strip()
    if not username:
        raise ValueError("Kullanıcı adı boş olamaz.")
    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        role=role,
        auth_source=AuthSource.local,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


async def set_user_role(session: AsyncSession, user_id: int, role: Role) -> bool:
    user = await session.get(User, user_id)
    if user is None:
        return False
    user.role = role
    await session.commit()
    return True


async def set_user_email(session: AsyncSession, user_id: int, email: str | None) -> bool:
    user = await session.get(User, user_id)
    if user is None:
        return False
    user.email = email
    await session.commit()
    return True


async def set_user_active(session: AsyncSession, user_id: int, active: bool) -> bool:
    user = await session.get(User, user_id)
    if user is None:
        return False
    user.is_active = active
    await session.commit()
    return True


async def set_user_password(session: AsyncSession, user_id: int, password: str) -> bool:
    """Kullanıcının parolasını (argon2 hash'le) günceller. Yerel hesaplar için."""
    user = await session.get(User, user_id)
    if user is None:
        return False
    user.password_hash = hash_password(password)
    await session.commit()
    return True


async def delete_user(session: AsyncSession, user_id: int) -> bool:
    user = await session.get(User, user_id)
    if user is None:
        return False
    await session.delete(user)
    await session.commit()
    return True


async def authenticate(session: AsyncSession, username: str, password: str) -> User | None:
    """Yerel kullanıcı/parola doğrulaması. Başarısızsa None."""
    user = await get_user_by_username(session, username)
    if user is None or not user.is_active or user.password_hash is None:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


def _ldap_default_role() -> Role:
    try:
        return Role(settings.ldap_default_role)
    except ValueError:
        return Role.viewer


async def get_or_create_ldap_user(session: AsyncSession, username: str) -> User | None:
    """LDAP doğrulaması sonrası yerel kaydı bulur ya da oluşturur (JIT provisioning).

    Var olan kullanıcı pasifse None döner. Yeni kullanıcı parolasız (password_hash
    NULL) ve auth_source=ldap olarak yapılandırılan varsayılan rolle oluşturulur.
    """
    user = await get_user_by_username(session, username)
    if user is not None:
        return user if user.is_active else None
    user = User(
        username=username,
        password_hash=None,
        role=_ldap_default_role(),
        auth_source=AuthSource.ldap,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


async def import_ldap_user(
    session: AsyncSession,
    username: str,
    role: Role,
    email: str | None = None,
    *,
    active: bool = True,
) -> tuple[User, bool]:
    """LDAP'tan bir kullanıcıyı içe aktarır (rol atayarak). (kullanıcı, yeni mi?) döndürür.

    Varsa rolü güncellenir (ve e-posta boşsa doldurulur); yoksa parolasız
    (auth_source=ldap) olarak oluşturulur. Giriş LDAP bind ile yapılır. ``active`` yeni
    kullanıcının başlangıç durumudur (grup içe aktarmada False → admin sonra etkinleştirir);
    var olan kullanıcının is_active'i değiştirilmez.
    """
    user = await get_user_by_username(session, username)
    if user is not None:
        # Var olan admin'i LDAP içe aktarmayla ASLA düşürme (kazara yetki kaybı koruması).
        if user.role != Role.admin:
            user.role = role
        if email and not user.email:
            user.email = email
        await session.commit()
        await session.refresh(user)
        return user, False
    user = User(
        username=username,
        email=email,
        password_hash=None,
        role=role,
        auth_source=AuthSource.ldap,
        is_active=active,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user, True


async def import_ldap_users(
    session: AsyncSession,
    members: list[tuple[str, str | None]],
    role: Role,
    *,
    active: bool = False,
) -> tuple[int, int]:
    """Bir grubun üyelerini toplu içe aktarır (varsayılan: pasif/disabled).

    members: (username, email) çiftleri. (yeni_sayısı, var_olan_sayısı) döndürür.
    Admin sonradan Kullanıcılar sayfasından etkinleştirir. **Var olan kullanıcılara
    dokunulmaz** (rolü/aktifliği değişmez) — toplu içe aktarma yalnızca yeni üyeleri ekler.
    """
    created = 0
    existing = 0
    for username, email in members:
        if await get_user_by_username(session, username) is not None:
            existing += 1  # mevcut kullanıcı: rol/durum korunur
            continue
        await import_ldap_user(session, username, role, email, active=active)
        created += 1
    return created, existing


async def authenticate_user(session: AsyncSession, username: str, password: str) -> User | None:
    """Yerel + (etkinse) LDAP kimlik doğrulaması. Login uçlarının kullandığı giriş noktası.

    - Kullanıcı yerel (auth_source=local) ise yalnızca yerel parola denenir.
    - Kullanıcı LDAP ise ya da hiç yoksa ve LDAP açıksa, LDAP bind denenir; başarılıysa
      yerel kayıt oluşturulur/bulunur (JIT). Aksi halde yerel doğrulamaya düşülür.
    """
    user = await get_user_by_username(session, username)
    if user is not None and user.auth_source == AuthSource.local:
        return await authenticate(session, username, password)

    if settings.ldap_enabled:
        if user is not None and not user.is_active:
            return None
        app_row = await get_settings(session)
        if await ldap_authenticate(
            username,
            password,
            verify_cert=app_row.ldaps_verify_cert,
            ca_cert=app_row.ldaps_ca_cert,
        ):
            return await get_or_create_ldap_user(session, username)
        return None

    # LDAP kapalı: yerel doğrulamaya düş (örn. var olan ama parolasız LDAP kaydı → None).
    return await authenticate(session, username, password)


# --- MFA (çok adımlı doğrulama) ---


def get_mfa_secret(user: User) -> str:
    """Kullanıcının şifreli TOTP sırrını çözer (yoksa boş dize)."""
    if not user.mfa_secret_encrypted:
        return ""
    return decrypt_secret(user.mfa_secret_encrypted)


async def begin_totp_enrollment(session: AsyncSession, user: User) -> str:
    """Yeni TOTP sırrı üretir ve şifreli saklar (henüz ETKİN DEĞİL); ham sırrı döndürür.

    Kullanıcı authenticator'ından bir kod girip ``confirm_totp`` ile doğrulayana kadar
    MFA etkinleşmez (yanlış kurulumla kilitlenmeyi önler).
    """
    secret = generate_totp_secret()
    user.mfa_method = "totp"
    user.mfa_secret_encrypted = encrypt_secret(secret)
    user.mfa_enabled = False
    await session.commit()
    return secret


async def confirm_totp(session: AsyncSession, user: User, code: str) -> bool:
    """Kayıt sırasında girilen TOTP kodunu doğrular; doğruysa MFA'yı etkinleştirir."""
    secret = get_mfa_secret(user)
    if user.mfa_method != "totp" or not secret:
        return False
    if not verify_totp(secret, code):
        return False
    user.mfa_enabled = True
    await session.commit()
    return True


async def begin_email_enrollment(session: AsyncSession, user: User) -> None:
    """E-posta OTP kaydını başlatır (yöntem=email, henüz ETKİN DEĞİL; TOTP sırrı temizlenir).

    Kod gönderimi ve doğrulaması çağıran katmanda (web) yapılır; kullanıcı e-postasına
    gelen kodu girip doğrulayana dek MFA etkinleşmez (yanlış e-posta ile kilitlenmeyi önler).
    """
    user.mfa_method = "email"
    user.mfa_secret_encrypted = None
    user.mfa_enabled = False
    await session.commit()


async def enable_mfa(session: AsyncSession, user: User) -> None:
    """Kaydı onaylanan kullanıcının MFA'sını etkinleştirir."""
    user.mfa_enabled = True
    await session.commit()


async def disable_mfa(session: AsyncSession, user: User) -> None:
    """Kullanıcının MFA'sını kapatır ve sırrı temizler."""
    user.mfa_method = "none"
    user.mfa_secret_encrypted = None
    user.mfa_enabled = False
    await session.commit()


async def disable_mfa_for_user(session: AsyncSession, user_id: int) -> bool:
    """Admin sıfırlaması: verilen kullanıcının MFA'sını kapatır (id ile)."""
    user = await session.get(User, user_id)
    if user is None:
        return False
    await disable_mfa(session, user)
    return True
