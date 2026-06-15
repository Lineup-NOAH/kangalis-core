"""LDAP login testleri: kullanıcı adı doğrulama + bind koruması + authenticate_user."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.config import settings
from cybersectool.core import ldap as ldap_mod
from cybersectool.core import users as users_mod
from cybersectool.core.ldap import ldap_authenticate, valid_ldap_username
from cybersectool.core.models import AuthSource, Role
from cybersectool.core.users import authenticate_user, create_user

# --- kullanıcı adı doğrulama (enjeksiyon koruması) ---


def test_valid_ldap_username() -> None:
    assert valid_ldap_username("alice")
    assert valid_ldap_username("alice.smith@corp.local")
    assert not valid_ldap_username("")  # boş
    assert not valid_ldap_username("a,b")  # DN ayracı
    assert not valid_ldap_username("a)(uid=*")  # filtre enjeksiyonu
    assert not valid_ldap_username("a" * 65)  # çok uzun


# --- LDAPS sertifika doğrulama (_make_server) ---


def test_make_server_validates_cert_when_enabled() -> None:
    import ssl

    server = ldap_mod._make_server("ldaps://dc.local:636", True, verify_cert=True, ca_cert=None)
    tls = getattr(server, "tls", None)
    assert tls is not None
    assert tls.validate == ssl.CERT_REQUIRED


def test_make_server_no_validation_when_disabled() -> None:
    import ssl

    server = ldap_mod._make_server("ldaps://dc.local:636", True, verify_cert=False)
    tls = getattr(server, "tls", None)
    # Doğrulama kapalı: tls yok ya da CERT_REQUIRED değil (eski davranış).
    assert tls is None or tls.validate != ssl.CERT_REQUIRED


def test_make_server_passes_ca_cert() -> None:
    pem = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"
    server = ldap_mod._make_server("ldaps://dc.local:636", True, verify_cert=True, ca_cert=pem)
    tls = getattr(server, "tls", None)
    assert tls is not None
    assert tls.ca_certs_data == pem


# --- ldap_authenticate koruması ---


async def test_ldap_disabled_returns_false() -> None:
    # Varsayılan: ldap kapalı → daima False
    assert await ldap_authenticate("alice", "pw") is False


async def test_ldap_empty_password_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "ldap_enabled", True)
    monkeypatch.setattr(settings, "ldap_server_uri", "ldap://dc.local:389")

    called = {"bind": False}

    def spy_bind(username: str, password: str, verify_cert: bool, ca_cert: str | None) -> bool:
        called["bind"] = True
        return True

    monkeypatch.setattr(ldap_mod, "_bind", spy_bind)
    # Boş parola → bind'e hiç gidilmeden reddedilir (unauthenticated bind koruması)
    assert await ldap_authenticate("alice", "") is False
    assert called["bind"] is False
    # Geçersiz kullanıcı adı → yine bind'e gidilmez
    assert await ldap_authenticate("a,b", "pw") is False
    assert called["bind"] is False


async def test_ldap_valid_calls_bind(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "ldap_enabled", True)
    monkeypatch.setattr(settings, "ldap_server_uri", "ldap://dc.local:389")
    monkeypatch.setattr(
        ldap_mod, "_bind", lambda u, p, verify_cert, ca_cert: u == "alice" and p == "secret"
    )
    assert await ldap_authenticate("alice", "secret") is True
    assert await ldap_authenticate("alice", "wrong") is False


# --- authenticate_user: yerel + LDAP orkestrasyonu ---


async def test_authenticate_user_local(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        await create_user(session, "bob", "pw12345", role=Role.analyst)
        assert (await authenticate_user(session, "bob", "pw12345")) is not None
        assert (await authenticate_user(session, "bob", "wrong")) is None


async def test_authenticate_user_ldap_jit_provision(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "ldap_enabled", True)
    monkeypatch.setattr(settings, "ldap_default_role", "analyst")

    async def fake_ldap(
        username: str, password: str, *, verify_cert: bool = False, ca_cert: str | None = None
    ) -> bool:
        return username == "carol" and password == "dirpass"

    monkeypatch.setattr(users_mod, "ldap_authenticate", fake_ldap)
    async with session_factory() as session:
        # İlk giriş → kullanıcı otomatik oluşturulur
        user = await authenticate_user(session, "carol", "dirpass")
        assert user is not None
        assert user.auth_source == AuthSource.ldap
        assert user.role == Role.analyst
        assert user.password_hash is None
        # İkinci giriş → aynı kayıt, kopya yok
        user2 = await authenticate_user(session, "carol", "dirpass")
        assert user2 is not None and user2.id == user.id


async def test_authenticate_user_ldap_fail(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "ldap_enabled", True)

    async def fake_ldap(
        username: str, password: str, *, verify_cert: bool = False, ca_cert: str | None = None
    ) -> bool:
        return False

    monkeypatch.setattr(users_mod, "ldap_authenticate", fake_ldap)
    async with session_factory() as session:
        assert (await authenticate_user(session, "dave", "x")) is None


async def test_local_user_not_authenticated_via_ldap(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "ldap_enabled", True)

    async def fake_ldap(
        username: str, password: str, *, verify_cert: bool = False, ca_cert: str | None = None
    ) -> bool:
        return True  # LDAP her şeye evet dese bile yerel kullanıcı LDAP'a gitmez

    monkeypatch.setattr(users_mod, "ldap_authenticate", fake_ldap)
    async with session_factory() as session:
        await create_user(session, "erin", "localpw")
        # Yanlış yerel parola → LDAP'a düşmeden None (auth_source=local)
        assert (await authenticate_user(session, "erin", "wrong")) is None
        # Doğru yerel parola → yerel doğrulama
        assert (await authenticate_user(session, "erin", "localpw")) is not None


# --- grup içe aktarma: üyeler PASİF gelir, mevcut kullanıcı pasifleşmez ---


async def test_import_ldap_users_disabled(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    from cybersectool.core.users import get_user_by_username, import_ldap_users

    async with session_factory() as session:
        # Mevcut etkin kullanıcı — grup içe aktarma onu pasifleştirmemeli.
        await create_user(session, "existing", "pw12345", role=Role.viewer)
        created, existing = await import_ldap_users(
            session,
            [("alice", "a@x"), ("bob", None), ("existing", None)],
            Role.viewer,
            active=False,
        )
        assert created == 2  # alice + bob yeni
        assert existing == 1  # existing zaten vardı
        alice = await get_user_by_username(session, "alice")
        assert alice is not None
        assert alice.is_active is False  # pasif geldi (admin sonra etkinleştirir)
        assert alice.auth_source == AuthSource.ldap
        assert alice.password_hash is None
        ex = await get_user_by_username(session, "existing")
        assert ex is not None and ex.is_active is True  # mevcut kullanıcı pasifleşmedi


async def test_import_ldap_users_preserves_existing_admin(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Toplu grup içe aktarma var olan admin'in rolünü/aktifliğini DEĞİŞTİRMEZ (W7 güvenlik)."""
    from cybersectool.core.users import get_user_by_username, import_ldap_users

    async with session_factory() as session:
        await create_user(session, "bossadmin", "pw12345", role=Role.admin)
        created, existing = await import_ldap_users(
            session, [("bossadmin", None), ("newbie", None)], Role.viewer, active=False
        )
        assert created == 1 and existing == 1
        boss = await get_user_by_username(session, "bossadmin")
        assert boss is not None
        assert boss.role == Role.admin  # viewer-grup içe aktarması admin'i DÜŞÜRMEDİ
        assert boss.is_active is True  # pasifleşmedi
        newbie = await get_user_by_username(session, "newbie")
        assert newbie is not None and newbie.is_active is False  # yeni → pasif


async def test_import_ldap_user_no_admin_downgrade(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Tekil LDAP içe aktarma da var olan admin'i düşürmez (kazara yetki kaybı koruması)."""
    from cybersectool.core.users import get_user_by_username, import_ldap_user

    async with session_factory() as session:
        await create_user(session, "adm", "pw12345", role=Role.admin)
        user, created = await import_ldap_user(session, "adm", Role.viewer)
        assert created is False
        assert user.role == Role.admin  # admin korundu
        _ = await get_user_by_username(session, "adm")
