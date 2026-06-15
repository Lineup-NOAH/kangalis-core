"""Web dashboard (HTML) akış testleri."""

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


async def test_login_page_renders(client: AsyncClient) -> None:
    resp = await client.get("/login")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "Kangalis" in resp.text


async def test_dashboard_redirects_anonymous(client: AsyncClient) -> None:
    resp = await client.get("/", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"


async def test_web_login_flow(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _seed(session_factory, "alice", "secret123", Role.admin)
    resp = await client.post(
        "/login",
        data={"username": "alice", "password": "secret123"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    home = await client.get("/")
    assert home.status_code == 200
    assert "alice" in home.text


async def test_web_login_bad_password(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _seed(session_factory, "bob", "rightpass")
    resp = await client.post("/login", data={"username": "bob", "password": "wrong"})
    assert resp.status_code == 401
