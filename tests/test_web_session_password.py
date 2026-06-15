"""Web: oturum idle zaman aşımı + kullanıcı oluşturmada parola politikası."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.app_settings import save_hardening_settings
from cybersectool.core.models import Role
from cybersectool.core.users import create_user, get_user_by_username


async def _login(
    client: AsyncClient,
    factory: async_sessionmaker[AsyncSession],
    username: str,
    role: Role = Role.admin,
) -> None:
    async with factory() as session:
        await create_user(session, username, "pass1234", role=role)
    await client.post("/auth/login", json={"username": username, "password": "pass1234"})


async def test_session_idle_logout(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cybersectool.web import routes

    await _login(client, session_factory, "idleu", Role.admin)
    ok = await client.get("/scans", follow_redirects=False)
    assert ok.status_code == 200
    # Idle süresi dolmuş gibi davran → korunan sayfa login'e yönlendirir, oturum temizlenir.
    monkeypatch.setattr(routes, "session_idle_expired", lambda s: True)
    expired = await client.get("/scans", follow_redirects=False)
    assert expired.status_code == 303
    assert expired.headers["location"] == "/login"


async def test_password_policy_blocks_weak(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "admp", Role.admin)
    async with session_factory() as session:
        await save_hardening_settings(
            session,
            session_timeout_min=0,
            password_min_length=12,
            password_require_complexity=True,
            ldaps_verify_cert=False,
        )
    # Zayıf parola (kısa + rakamsız) → 400, kullanıcı oluşmaz.
    weak = await client.post(
        "/users/create",
        data={"username": "weakling", "password": "short", "role": "viewer"},
        follow_redirects=False,
    )
    assert weak.status_code == 400
    async with session_factory() as session:
        assert await get_user_by_username(session, "weakling") is None
    # Politikaya uyan parola → 303, kullanıcı oluşur.
    strong = await client.post(
        "/users/create",
        data={"username": "strongling", "password": "Abcdef123456", "role": "viewer"},
        follow_redirects=False,
    )
    assert strong.status_code == 303
    async with session_factory() as session:
        assert await get_user_by_username(session, "strongling") is not None


async def test_create_user_persists_email(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Kullanıcı oluşturmada e-posta alanı kaydedilir."""
    await _login(client, session_factory, "adme", Role.admin)
    resp = await client.post(
        "/users/create",
        data={
            "username": "withmail",
            "password": "Abcdef123456",
            "role": "viewer",
            "email": "  who@x  ",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    async with session_factory() as session:
        created = await get_user_by_username(session, "withmail")
        assert created is not None and created.email == "who@x"  # strip uygulandı


async def test_scans_page_shows_assignment_for_admin(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Admin için Taramalar sayfası atama select'ini render eder."""
    await _login(client, session_factory, "admscan", Role.admin)
    resp = await client.get("/scans")
    assert resp.status_code == 200
    assert "Kullanıcıya ata" in resp.text


async def test_scans_page_no_assignment_for_analyst(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Analist için atama bloğu gösterilmez (yalnız admin atayabilir)."""
    await _login(client, session_factory, "anscan", Role.analyst)
    resp = await client.get("/scans")
    assert resp.status_code == 200
    assert "Kullanıcıya ata" not in resp.text
