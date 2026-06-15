"""Kullanıcıya özel token paneli (/tokens) + core list/revoke testleri."""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.models import ApiToken, Role
from cybersectool.core.tokens import create_api_token, list_user_tokens, revoke_user_token
from cybersectool.core.users import create_user

# --- core: sahiplik kontrolü ---


async def test_list_and_revoke_ownership(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        u1 = await create_user(session, "u1", "pw123456")
        u2 = await create_user(session, "u2", "pw123456")
        t1, _ = await create_api_token(session, u1.id, "u1-token")
        await create_api_token(session, u2.id, "u2-token")

        # Her kullanıcı yalnızca kendi token'ını görür
        assert len(await list_user_tokens(session, u1.id)) == 1
        assert (await list_user_tokens(session, u1.id))[0].name == "u1-token"

        # u2, u1'in token'ını iptal EDEMEZ
        assert await revoke_user_token(session, t1.id, u2.id) is False
        # u1 kendi token'ını iptal edebilir
        assert await revoke_user_token(session, t1.id, u1.id) is True
        refreshed = await session.get(ApiToken, t1.id)
        assert refreshed is not None and refreshed.revoked is True


# --- web UI ---


async def _login(client: AsyncClient, factory: async_sessionmaker[AsyncSession], name: str) -> None:
    async with factory() as session:
        await create_user(session, name, "pw123456", role=Role.viewer)
    await client.post("/auth/login", json={"username": name, "password": "pw123456"})


async def test_tokens_page_requires_auth(client: AsyncClient) -> None:
    resp = await client.get("/tokens", follow_redirects=False)
    assert resp.status_code == 303


async def test_create_token_shows_raw_once(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "alice")
    resp = await client.post("/tokens/create", data={"name": "mcp-claude", "expires_days": "0"})
    assert resp.status_code == 200
    assert "cst_" in resp.text  # ham token bir kez gösterilir
    assert "mcp-claude" in resp.text
    # Yeni "nasıl kullanılır": IP girişi + hazır Claude bağlama snippet'i (token gömülü).
    assert 'id="mcp-ip"' in resp.text
    assert "claude mcp add" in resp.text
    assert ":8001/mcp" in resp.text

    # Sonraki düz liste ham token'ı GÖSTERMEZ
    page = await client.get("/tokens")
    assert page.status_code == 200
    assert "mcp-claude" in page.text
    assert "cst_" not in page.text


async def test_create_token_empty_name_rejected(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "bob")
    resp = await client.post("/tokens/create", data={"name": "   ", "expires_days": "0"})
    assert resp.status_code == 400
    assert "boş olamaz" in resp.text


async def test_revoke_token_web(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "carol")
    await client.post("/tokens/create", data={"name": "t1", "expires_days": "0"})
    # token id'sini DB'den al
    async with session_factory() as session:
        from cybersectool.core.users import get_user_by_username

        user = await get_user_by_username(session, "carol")
        assert user is not None
        tokens = await list_user_tokens(session, user.id)
        token_id = tokens[0].id

    resp = await client.post(f"/tokens/{token_id}/revoke", follow_redirects=False)
    assert resp.status_code == 303
    async with session_factory() as session:
        tok = await session.get(ApiToken, token_id)
        assert tok is not None and tok.revoked is True


async def test_cannot_revoke_others_token_web(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    # Başka kullanıcının (dave) token'ı
    async with session_factory() as session:
        dave = await create_user(session, "dave", "pw123456")
        dave_token, _ = await create_api_token(session, dave.id, "dave-token")
        dave_token_id = dave_token.id

    # erin olarak giriş yap, dave'in token'ını iptal etmeye çalış
    await _login(client, session_factory, "erin")
    resp = await client.post(f"/tokens/{dave_token_id}/revoke", follow_redirects=False)
    assert resp.status_code == 303  # yine yönlendirir ama iptal ETMEZ
    async with session_factory() as session:
        tok = await session.get(ApiToken, dave_token_id)
        assert tok is not None and tok.revoked is False  # hâlâ aktif
