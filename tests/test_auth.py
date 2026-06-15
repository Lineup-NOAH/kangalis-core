"""Auth + RBAC akış testleri."""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.models import Role
from cybersectool.core.users import create_user


async def _seed(
    factory: async_sessionmaker[AsyncSession],
    username: str,
    password: str,
    role: Role = Role.viewer,
) -> None:
    async with factory() as session:
        await create_user(session, username, password, role=role)


async def test_me_requires_auth(client: AsyncClient) -> None:
    resp = await client.get("/auth/me")
    assert resp.status_code == 401


async def test_login_then_me(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _seed(session_factory, "alice", "secret123", Role.analyst)
    login = await client.post("/auth/login", json={"username": "alice", "password": "secret123"})
    assert login.status_code == 200
    me = await client.get("/auth/me")
    assert me.status_code == 200
    body = me.json()
    assert body["username"] == "alice"
    assert body["role"] == "analyst"


async def test_wrong_password(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _seed(session_factory, "bob", "rightpass")
    resp = await client.post("/auth/login", json={"username": "bob", "password": "wrong"})
    assert resp.status_code == 401


async def test_rbac_viewer_forbidden(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _seed(session_factory, "vi", "viewerpass", Role.viewer)
    await client.post("/auth/login", json={"username": "vi", "password": "viewerpass"})
    resp = await client.get("/admin/ping")
    assert resp.status_code == 403


async def test_rbac_admin_allowed(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _seed(session_factory, "adm", "adminpass", Role.admin)
    await client.post("/auth/login", json={"username": "adm", "password": "adminpass"})
    resp = await client.get("/admin/ping")
    assert resp.status_code == 200
    assert resp.json()["status"] == "admin-ok"
