"""Kullanıcı düzenle (admin: rol + e-posta + MFA yönetimi) web akışı testleri.

/account (Hesabım) self-servis sayfası kaldırıldı; bu testler onun yerini alır.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.models import Role
from cybersectool.core.users import (
    create_user,
    get_mfa_secret,
    get_user_by_id,
)
from tests.test_mfa_email import FakeRedis


async def _login(
    client: AsyncClient,
    factory: async_sessionmaker[AsyncSession],
    username: str,
    role: Role = Role.admin,
) -> int:
    async with factory() as session:
        user = await create_user(session, username, "pass1234", role=role)
        uid = user.id
    await client.post("/auth/login", json={"username": username, "password": "pass1234"})
    return uid


async def _make_target(
    factory: async_sessionmaker[AsyncSession],
    username: str,
    *,
    role: Role = Role.viewer,
    email: str | None = None,
) -> int:
    async with factory() as session:
        user = await create_user(session, username, "pass1234", role=role, email=email)
        return user.id


async def test_admin_edit_page_renders(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "admin1")
    target_id = await _make_target(session_factory, "victim")
    resp = await client.get(f"/users/{target_id}/edit")
    assert resp.status_code == 200
    assert "victim" in resp.text
    assert 'name="role"' in resp.text


async def test_non_admin_edit_redirects(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "viewer1", role=Role.viewer)
    target_id = await _make_target(session_factory, "victim2")
    resp = await client.get(f"/users/{target_id}/edit", follow_redirects=False)
    assert resp.status_code == 303


async def test_admin_edit_save_role_and_email(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "admin2")
    target_id = await _make_target(session_factory, "edituser", role=Role.viewer)
    resp = await client.post(
        f"/users/{target_id}/edit",
        data={"role": "analyst", "email": "edit@corp"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    async with session_factory() as session:
        user = await get_user_by_id(session, target_id)
        assert user is not None
        assert user.role == Role.analyst
        assert user.email == "edit@corp"


async def test_admin_self_demote_guarded(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    admin_id = await _login(client, session_factory, "admin3")
    # Admin kendi rolünü viewer'a düşürmeye çalışır → rol korunur, e-posta yine güncellenir.
    resp = await client.post(
        f"/users/{admin_id}/edit",
        data={"role": "viewer", "email": "me@corp"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    async with session_factory() as session:
        user = await get_user_by_id(session, admin_id)
        assert user is not None
        assert user.role == Role.admin  # self-guard: değişmedi
        assert user.email == "me@corp"


async def test_admin_totp_setup_and_enable(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "admin4")
    target_id = await _make_target(session_factory, "totpuser")

    setup = await client.post(f"/users/{target_id}/mfa/totp/setup", follow_redirects=False)
    assert setup.status_code == 303
    async with session_factory() as session:
        user = await get_user_by_id(session, target_id)
        assert user is not None
        assert user.mfa_method == "totp"
        assert user.mfa_enabled is False
        assert get_mfa_secret(user) != ""

    # Edit sayfası artık QR (SVG) + sırrı gösterir.
    page = await client.get(f"/users/{target_id}/edit")
    assert page.status_code == 200
    assert "<svg" in page.text
    async with session_factory() as session:
        user = await get_user_by_id(session, target_id)
        assert user is not None
        assert get_mfa_secret(user) in page.text

    enable = await client.post(f"/users/{target_id}/mfa/totp/enable", follow_redirects=False)
    assert enable.status_code == 303
    async with session_factory() as session:
        user = await get_user_by_id(session, target_id)
        assert user is not None
        assert user.mfa_enabled is True


async def test_admin_email_mfa_enable(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cybersectool.core import mfa_email
    from cybersectool.core.app_settings import save_smtp_settings

    monkeypatch.setattr(mfa_email, "_redis", lambda: FakeRedis())

    await _login(client, session_factory, "admin5")
    target_id = await _make_target(session_factory, "emailuser", email="e@corp")
    async with session_factory() as session:
        await save_smtp_settings(
            session,
            enabled=True,
            host="smtp.x",
            port=587,
            username="u",
            sender="f@x",
            use_tls=True,
            alert_to="",
            password="p",
        )

    resp = await client.post(f"/users/{target_id}/mfa/email/enable", follow_redirects=False)
    assert resp.status_code == 303
    async with session_factory() as session:
        user = await get_user_by_id(session, target_id)
        assert user is not None
        assert user.mfa_enabled is True
        assert user.mfa_method == "email"


async def test_admin_email_mfa_blocked_without_email(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    await _login(client, session_factory, "admin6")
    target_id = await _make_target(session_factory, "noemailuser", email=None)
    # SMTP etkin olsa bile e-posta yoksa etkinleşmez.
    resp = await client.post(f"/users/{target_id}/mfa/email/enable", follow_redirects=False)
    assert resp.status_code == 303
    async with session_factory() as session:
        user = await get_user_by_id(session, target_id)
        assert user is not None
        assert user.mfa_enabled is False


async def test_admin_email_mfa_blocked_without_smtp(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    await _login(client, session_factory, "admin7")
    target_id = await _make_target(session_factory, "smtplessuser", email="e@corp")
    # E-posta var ama SMTP kapalı → etkinleşmez.
    resp = await client.post(f"/users/{target_id}/mfa/email/enable", follow_redirects=False)
    assert resp.status_code == 303
    async with session_factory() as session:
        user = await get_user_by_id(session, target_id)
        assert user is not None
        assert user.mfa_enabled is False


async def test_admin_mfa_disable(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "admin8")
    target_id = await _make_target(session_factory, "disableuser")
    await client.post(f"/users/{target_id}/mfa/totp/setup", follow_redirects=False)
    await client.post(f"/users/{target_id}/mfa/totp/enable", follow_redirects=False)

    resp = await client.post(f"/users/{target_id}/mfa/disable", follow_redirects=False)
    assert resp.status_code == 303
    async with session_factory() as session:
        user = await get_user_by_id(session, target_id)
        assert user is not None
        assert user.mfa_enabled is False
        assert user.mfa_method == "none"
        assert user.mfa_secret_encrypted is None


async def test_account_page_removed(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "admin9")
    resp = await client.get("/account", follow_redirects=False)
    assert resp.status_code == 404


# --- X-5: yönetim (pasifleştir/etkinleştir + sil) düzenle alanında ---
async def test_edit_page_shows_management(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Düzenle sayfası, başka bir kullanıcı için toggle + sil formlarını gösterir."""
    await _login(client, session_factory, "adm_mgmt")
    target_id = await _make_target(session_factory, "mgmtuser")
    page = await client.get(f"/users/{target_id}/edit")
    assert page.status_code == 200
    assert f"/users/{target_id}/toggle" in page.text
    assert f"/users/{target_id}/delete" in page.text


async def test_admin_toggle_user_redirects_to_edit(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Toggle: is_active ters döner + düzenle sayfasına yönlendirir."""
    await _login(client, session_factory, "adm_tg")
    target_id = await _make_target(session_factory, "tguser")  # default aktif
    resp = await client.post(f"/users/{target_id}/toggle", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == f"/users/{target_id}/edit"
    async with session_factory() as session:
        user = await get_user_by_id(session, target_id)
        assert user is not None and user.is_active is False


async def test_admin_delete_user(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Admin başka kullanıcıyı siler → kullanıcı kaybolur."""
    await _login(client, session_factory, "adm_del")
    target_id = await _make_target(session_factory, "deluser")
    resp = await client.post(f"/users/{target_id}/delete", follow_redirects=False)
    assert resp.status_code == 303
    async with session_factory() as session:
        assert await get_user_by_id(session, target_id) is None


async def test_admin_cannot_delete_self(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Admin kendini silemez (no-op) — hesap durur."""
    admin_id = await _login(client, session_factory, "adm_self")
    resp = await client.post(f"/users/{admin_id}/delete", follow_redirects=False)
    assert resp.status_code == 303
    async with session_factory() as session:
        assert await get_user_by_id(session, admin_id) is not None


async def test_edit_page_self_hides_management(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Kendi düzenle sayfasında toggle/sil gösterilmez (kendini yönetemez)."""
    admin_id = await _login(client, session_factory, "adm_selfmgmt")
    page = await client.get(f"/users/{admin_id}/edit")
    assert page.status_code == 200
    assert f"/users/{admin_id}/toggle" not in page.text
    assert f"/users/{admin_id}/delete" not in page.text
