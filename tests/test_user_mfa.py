"""Kullanıcı MFA servis fonksiyonları (kayıt/doğrula/kapat) testleri."""

from __future__ import annotations

import pyotp
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.users import (
    begin_totp_enrollment,
    confirm_totp,
    create_user,
    disable_mfa,
    get_mfa_secret,
)


async def test_totp_enrollment_flow(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        user = await create_user(session, "alice", "pw12345")
        secret = await begin_totp_enrollment(session, user)
        # Kayıt başladı ama henüz ETKİN değil; sır şifreli round-trip.
        assert user.mfa_method == "totp"
        assert user.mfa_enabled is False
        assert user.mfa_secret_encrypted is not None
        assert user.mfa_secret_encrypted != secret  # düz metin saklanmaz
        assert get_mfa_secret(user) == secret
        # Yanlış kod → etkinleşmez.
        assert await confirm_totp(session, user, "12") is False
        assert user.mfa_enabled is False
        # Doğru kod → etkinleşir.
        code = pyotp.TOTP(secret).now()
        assert await confirm_totp(session, user, code) is True
        assert user.mfa_enabled is True
        # Kapat → sır temizlenir.
        await disable_mfa(session, user)
        assert user.mfa_method == "none"
        assert user.mfa_enabled is False
        assert user.mfa_secret_encrypted is None


async def test_confirm_totp_without_enrollment(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        user = await create_user(session, "bob", "pw12345")
        # Kayıt yokken doğrulama her zaman False.
        assert await confirm_totp(session, user, "123456") is False
        assert user.mfa_enabled is False
