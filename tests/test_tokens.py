"""API token akış testleri (Bearer auth + iptal)."""

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


async def test_token_create_and_use(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _seed(session_factory, "alice", "secret123", Role.admin)
    await client.post("/auth/login", json={"username": "alice", "password": "secret123"})

    created = await client.post("/auth/tokens", json={"name": "mcp"})
    assert created.status_code == 200
    raw = created.json()["token"]
    assert raw.startswith("cst_")

    # Token-only: oturum cookie'sini temizle, yalnızca Bearer kullan
    client.cookies.clear()
    headers = {"Authorization": f"Bearer {raw}"}

    me = await client.get("/auth/me", headers=headers)
    assert me.status_code == 200
    assert me.json()["username"] == "alice"

    admin = await client.get("/admin/ping", headers=headers)
    assert admin.status_code == 200


async def test_revoked_token_rejected(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _seed(session_factory, "bob", "secret123", Role.viewer)
    await client.post("/auth/login", json={"username": "bob", "password": "secret123"})
    created = await client.post("/auth/tokens", json={"name": "t1"})
    token_id = created.json()["id"]
    raw = created.json()["token"]

    revoke = await client.delete(f"/auth/tokens/{token_id}")
    assert revoke.status_code == 200

    client.cookies.clear()
    me = await client.get("/auth/me", headers={"Authorization": f"Bearer {raw}"})
    assert me.status_code == 401


async def test_invalid_token_rejected(client: AsyncClient) -> None:
    me = await client.get("/auth/me", headers={"Authorization": "Bearer cst_gecersiz"})
    assert me.status_code == 401
