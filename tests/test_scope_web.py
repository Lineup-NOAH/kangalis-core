"""#C: Yetkili tarama kapsamı (ScopePolicy) web formu — set_scope CLI yerine.

set_active_scope eski politikayı pasifleştirip yenisini aktif eder (validate_target bunu
okur — okuma mantığı DEĞİŞMEZ). Web formu admin-gated; CIDR doğrular; en az bir izinli
CIDR zorunlu (yanlışlıkla tüm-reddi önler). Genel web-CLI YOK.
"""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.models import Role
from cybersectool.core.scope import get_active_policy, is_target_allowed, set_active_scope
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


async def test_set_active_scope_deactivates_old_activates_new(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """İkinci yazım birincisini pasifleştirir; en yeni aktif olur + validate mantığı okur."""
    async with session_factory() as s:
        await set_active_scope(s, name="a", allowed_cidrs=["10.0.0.0/8"], denied_cidrs=[])
        await set_active_scope(
            s, name="b", allowed_cidrs=["192.168.1.0/24"], denied_cidrs=["192.168.1.1/32"]
        )
    async with session_factory() as s:
        active = await get_active_policy(s)
        assert active is not None
        assert active.name == "b"  # en yeni aktif
        assert active.allowed_cidrs == ["192.168.1.0/24"]
        assert active.denied_cidrs == ["192.168.1.1/32"]
        # validate_target bunu okur: deny kazanır, kapsam-dışı reddedilir
        assert is_target_allowed("192.168.1.50", active.allowed_cidrs, active.denied_cidrs)
        assert not is_target_allowed("192.168.1.1", active.allowed_cidrs, active.denied_cidrs)
        assert not is_target_allowed("10.0.0.5", active.allowed_cidrs, active.denied_cidrs)


async def test_scope_form_admin_writes_policy(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Admin formu gönderince yeni aktif ScopePolicy yazılır (CIDR'ler normalize)."""
    await _login(client, session_factory, "sc_adm", Role.admin)
    resp = await client.post(
        "/settings/scope",
        data={
            "name": "ic-ag",
            "allowed_cidrs": "192.168.0.0/16\n10.0.0.0/8",
            "denied_cidrs": "10.1.2.3/32",
        },
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303)
    async with session_factory() as s:
        active = await get_active_policy(s)
        assert active is not None
        assert active.allowed_cidrs == ["192.168.0.0/16", "10.0.0.0/8"]
        assert active.denied_cidrs == ["10.1.2.3/32"]


async def test_scope_form_empty_allowed_rejected(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Geçerli izinli CIDR yoksa 400 + politika YAZILMAZ (kilitlemeyi önler)."""
    await _login(client, session_factory, "sc_adm2", Role.admin)
    resp = await client.post(
        "/settings/scope",
        data={"name": "x", "allowed_cidrs": "  \ngecersiz-cidr-degil\n", "denied_cidrs": ""},
    )
    assert resp.status_code == 400
    async with session_factory() as s:
        assert await get_active_policy(s) is None


async def test_scope_form_non_admin_redirected(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Admin olmayan kapsam yazamaz (yönlendirilir, politika yok)."""
    await _login(client, session_factory, "sc_an", Role.analyst)
    resp = await client.post(
        "/settings/scope", data={"allowed_cidrs": "10.0.0.0/8"}, follow_redirects=False
    )
    assert resp.status_code in (302, 303)
    async with session_factory() as s:
        assert await get_active_policy(s) is None


async def test_settings_page_shows_scope_section(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Ayarlar sayfasında kapsam formu render edilir (admin)."""
    await _login(client, session_factory, "sc_adm3", Role.admin)
    resp = await client.get("/settings")
    assert resp.status_code == 200
    assert "/settings/scope" in resp.text
