"""LDAP kullanıcı yönetimi: config kaydı/şifreleme + arama sarmalayıcı + içe aktarma + web."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core import ldap as ldap_mod
from cybersectool.core.ldap import LdapSearchError, LdapUser, ldap_search_users
from cybersectool.core.ldap_config import get_bind_password, get_ldap_config, save_ldap_config
from cybersectool.core.models import AuthSource, LdapConfig, Role
from cybersectool.core.users import create_user, get_user_by_username, import_ldap_user


async def test_save_and_get_ldap_config(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        cfg = await save_ldap_config(
            session,
            server_uri="ldap://x:389",
            use_ssl=False,
            bind_dn="cn=admin,dc=x",
            base_dn="dc=x",
            user_filter="(objectClass=person)",
            attr_username="uid",
            attr_email="mail",
            attr_display_name="cn",
            default_role="analyst",
            bind_password="secret",
        )
        assert cfg.id == 1
        # Parola şifreli saklanır (düz metin değil), çözülebilir.
        assert cfg.bind_password_encrypted and cfg.bind_password_encrypted != "secret"
        assert get_bind_password(cfg) == "secret"

        # Boş parola ile güncelleme → mevcut şifreli parola korunur.
        cfg2 = await save_ldap_config(
            session,
            server_uri="ldap://y:389",
            use_ssl=True,
            bind_dn="cn=admin,dc=x",
            base_dn="dc=x",
            user_filter="(objectClass=person)",
            attr_username="uid",
            attr_email="mail",
            attr_display_name="cn",
            default_role="viewer",
            bind_password=None,
        )
        assert cfg2.server_uri == "ldap://y:389"
        assert cfg2.use_ssl is True
        assert get_bind_password(cfg2) == "secret"
        fetched = await get_ldap_config(session)
        assert fetched is not None and fetched.server_uri == "ldap://y:389"


async def test_import_ldap_user(session_factory: async_sessionmaker[AsyncSession]) -> None:
    async with session_factory() as session:
        user, created = await import_ldap_user(session, "alice", Role.analyst, email="alice@x")
        assert created is True
        assert user.auth_source == AuthSource.ldap
        assert user.password_hash is None
        assert user.role == Role.analyst
        # Tekrar içe aktar → güncelle (yeni rol), kopya oluşturma.
        user2, created2 = await import_ldap_user(session, "alice", Role.admin)
        assert created2 is False
        assert user2.id == user.id and user2.role == Role.admin


async def test_ldap_search_users_wrapper(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_search(
        config: object,
        bind_password: str,
        query: str,
        verify_cert: bool,
        ca_cert: str | None,
    ) -> list[LdapUser]:
        return [LdapUser(username="bob", email="bob@x", display_name="Bob", dn="uid=bob,dc=x")]

    monkeypatch.setattr(ldap_mod, "_search_users", fake_search)
    cfg = LdapConfig(id=1, server_uri="ldap://x", base_dn="dc=x")
    res = await ldap_search_users(cfg, "pw", "bob")
    assert len(res) == 1 and res[0].username == "bob"


async def test_ldap_search_requires_config() -> None:
    cfg = LdapConfig(id=1, server_uri="", base_dn="")
    with pytest.raises(LdapSearchError):
        await ldap_search_users(cfg, "", "x")


# --- web ---


async def _login(
    client: AsyncClient,
    factory: async_sessionmaker[AsyncSession],
    username: str,
    role: Role,
) -> None:
    async with factory() as session:
        await create_user(session, username, "pass1234", role=role)
    await client.post("/auth/login", json={"username": username, "password": "pass1234"})


async def test_ldap_page_admin(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Bağlantı → Ayarlar, kullanıcı arama/içe aktarma → Kullanıcılar."""
    await _login(client, session_factory, "adm1", Role.admin)
    # Ayarlar sayfasında LDAP bağlantı bölümü.
    resp = await client.get("/settings")
    assert resp.status_code == 200
    assert "LDAP Bağlantısı" in resp.text
    assert 'name="server_uri"' in resp.text
    # Kullanıcılar sayfasında içe aktarma bölümü.
    resp_users = await client.get("/users")
    assert resp_users.status_code == 200
    assert "LDAP'tan içe aktar" in resp_users.text


async def test_ldap_status_fragment(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Config yokken /ldap/status admin'e 'yapılandırılmamış' parçası döner."""
    await _login(client, session_factory, "adm3", Role.admin)
    resp = await client.get("/ldap/status")
    assert resp.status_code == 200
    assert "yapılandırılmamış" in resp.text


async def test_ldap_test_no_uri_returns_fragment(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Sunucu adresi boşken /ldap/test canlı 'Bağlı değil' parçası döner (redirect değil)."""
    await _login(client, session_factory, "adm5", Role.admin)
    resp = await client.post("/ldap/test", data={"server_uri": ""}, follow_redirects=False)
    assert resp.status_code == 200
    assert "Bağlı değil" in resp.text


async def test_ldap_test_uses_form_values_without_saving(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Kaydedilmemiş form değerleriyle test → canlı '● Bağlı' parçası; config DB'ye yazılmaz."""
    await _login(client, session_factory, "adm6", Role.admin)

    async def fake_test(
        config: LdapConfig,
        password: str,
        *,
        verify_cert: bool = False,
        ca_cert: str | None = None,
    ) -> tuple[bool, str]:
        assert config.server_uri == "ldap://fresh:389"
        return True, "ok"

    monkeypatch.setattr("cybersectool.web.routes.ldap_test_connection", fake_test)
    resp = await client.post(
        "/ldap/test",
        data={"server_uri": "ldap://fresh:389", "bind_dn": "", "bind_password": ""},
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert "● Bağlı" in resp.text
    # Test config'i KAYDETMEMELİ (kaydetmeden test felsefesi).
    async with session_factory() as session:
        assert await get_ldap_config(session) is None


async def test_ldap_legacy_redirects_to_settings(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Eski /ldap sayfası geriye dönük uyumluluk için /settings'e yönlendirir."""
    await _login(client, session_factory, "adm4", Role.admin)
    resp = await client.get("/ldap", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/settings"


async def test_ldap_page_non_admin_redirect(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "an1", Role.analyst)
    resp = await client.get("/settings", follow_redirects=False)
    assert resp.status_code == 303
    resp_users = await client.get("/users", follow_redirects=False)
    assert resp_users.status_code == 303


async def test_ldap_save_config_and_import(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "adm2", Role.admin)
    resp = await client.post(
        "/ldap/config",
        data={
            "server_uri": "ldap://dc.local:389",
            "base_dn": "ou=people,dc=corp,dc=local",
            "bind_dn": "cn=admin,dc=corp,dc=local",
            "bind_password": "svcpass",
            "user_filter": "(objectClass=person)",
            "attr_username": "uid",
            "attr_email": "mail",
            "attr_display_name": "cn",
            "default_role": "analyst",
            "use_ssl": "on",
        },
        follow_redirects=False,
    )
    # Config kaydı artık Ayarlar sayfasına yönlendirir.
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/settings")
    async with session_factory() as session:
        cfg = await get_ldap_config(session)
        assert cfg is not None and cfg.server_uri == "ldap://dc.local:389"
        assert cfg.use_ssl is True
        assert get_bind_password(cfg) == "svcpass"

    # Kullanıcı içe aktar (rol atayarak) → Kullanıcılar sayfasına yönlendirir.
    resp2 = await client.post(
        "/ldap/import",
        data={"username": "carol", "role": "analyst", "email": "carol@corp"},
        follow_redirects=False,
    )
    assert resp2.status_code == 303
    assert resp2.headers["location"].startswith("/users")
    async with session_factory() as session:
        u = await get_user_by_username(session, "carol")
        assert u is not None and u.role == Role.analyst
        assert u.auth_source == AuthSource.ldap
