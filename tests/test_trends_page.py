"""#D: /trends haftalık trend = 'yeni açılan' (kümülatif değil) — sayfa render + relabel."""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.models import Role
from cybersectool.core.users import create_user


async def _login(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    username: str,
    role: Role,
) -> None:
    async with session_factory() as s:
        await create_user(s, username, "pass1234", role=role)
    await client.post(
        "/login", data={"username": username, "password": "pass1234"}, follow_redirects=False
    )


async def test_trends_page_renders_newly_opened_label(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """/trends 200 render olur ve haftalık başlık artık 'yeni açılan' (relabel)."""
    await _login(client, session_factory, "tr_user", Role.analyst)
    resp = await client.get("/trends")
    assert resp.status_code == 200
    assert "yeni açılan" in resp.text.lower()  # trend_weekly_open relabeled (TR varsayılan)
