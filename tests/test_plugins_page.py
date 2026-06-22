"""#218/#219: Eklentiler (/plugins) paneli — OSS varyantı.

Canlı satırlar yalnız nmap + AI (yapılandırma formu Ayarlar'dan buraya taşındı). Sömürü
eklentileri (searchsploit/Metasploit/sandbox) bu çekirdekte YOK → yalnız nötr teaser kartı;
canlı durum satırı / kurulum kılavuzu / brute toggle OLMAZ. Sayfa admin-gated.
"""

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


async def test_plugins_page_admin_renders_oss_variant(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Admin: /plugins 200 — taşınan AI formu + nötr sömürü-eklentisi teaser'ı görünür."""
    await _login(client, session_factory, "adm_plg", Role.admin)
    resp = await client.get("/plugins")
    assert resp.status_code == 200
    body = resp.text
    assert "/plugins/ai" in body  # AI yapılandırma formu Eklentiler'e taşındı (#219)
    assert "kangalis-exploit" in body  # nötr "ayrı ticari eklenti" teaser'ı
    # Stripped modüller CANLI satır/kapı OLMAMALI:
    assert "/plugins/brute/toggle" not in body


async def test_plugins_page_non_admin_redirected(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Admin olmayan /plugins'e erişemez (anasayfaya yönlendirilir)."""
    await _login(client, session_factory, "an_plg", Role.analyst)
    resp = await client.get("/plugins", follow_redirects=False)
    assert resp.status_code in (302, 303)
