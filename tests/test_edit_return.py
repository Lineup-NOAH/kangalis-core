"""Düzenleme sonrası dönüş yolu (return_to) testleri — sihirbazdan açılan edit'ler.

Bug: Taramalar sihirbazından IP zone / kimlik / kimlik-zone düzenleyip kaydedince
kullanıcı /scans yerine /zones ya da /credentials'a atılıyordu. Düzeltme: return_to
ile geldiği yere döner; bilinmeyen değer güvenli varsayılana düşer (open-redirect yok).
"""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.credentials import create_credential, create_credential_zone
from cybersectool.core.models import CredentialType, Role
from cybersectool.core.users import create_user
from cybersectool.core.zones import create_zone


async def _admin(client: AsyncClient, fac: async_sessionmaker[AsyncSession], u: str) -> None:
    async with fac() as session:
        await create_user(session, u, "pass1234", role=Role.admin)
    await client.post(
        "/login", data={"username": u, "password": "pass1234"}, follow_redirects=False
    )


async def test_zone_edit_returns_to_scans(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """return_to=scans → kaydedince /scans'e döner (sihirbazdan gelindi)."""
    async with session_factory() as session:
        zone = await create_zone(session, "Z", ["10.0.0.0/24"])
        zid = zone.id
    await _admin(client, session_factory, "er_z1")
    resp = await client.post(
        f"/zones/{zid}/edit",
        data={"name": "Z", "cidrs": "10.0.0.0/24", "return_to": "scans"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/scans")


async def test_zone_edit_default_returns_to_zones(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """return_to verilmezse → /zones (katalog davranışı korunur)."""
    async with session_factory() as session:
        zone = await create_zone(session, "Z2", ["10.0.0.0/24"])
        zid = zone.id
    await _admin(client, session_factory, "er_z2")
    resp = await client.post(
        f"/zones/{zid}/edit",
        data={"name": "Z2", "cidrs": "10.0.0.0/24"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/zones")


async def test_zone_edit_rejects_open_redirect(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """return_to harici URL ise güvenli varsayılana düşer (open-redirect yok)."""
    async with session_factory() as session:
        zone = await create_zone(session, "Z3", ["10.0.0.0/24"])
        zid = zone.id
    await _admin(client, session_factory, "er_z3")
    resp = await client.post(
        f"/zones/{zid}/edit",
        data={"name": "Z3", "cidrs": "10.0.0.0/24", "return_to": "https://evil.example"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    loc = resp.headers["location"]
    assert loc.startswith("/zones")
    assert "evil.example" not in loc


async def test_credential_edit_returns_to_scans(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Kimlik düzenleme: return_to=scans → /scans."""
    async with session_factory() as session:
        cred = await create_credential(session, "c1", CredentialType.ssh, "root", "x")
        cid = cred.id
    await _admin(client, session_factory, "er_c1")
    resp = await client.post(
        f"/credentials/{cid}/edit",
        data={"name": "c1", "username": "root", "cred_type": "ssh", "return_to": "scans"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/scans")


async def test_credential_zone_edit_returns_to_scans(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Kimlik bölgesi düzenleme: return_to=scans → /scans."""
    async with session_factory() as session:
        cred = await create_credential(session, "c2", CredentialType.ssh, "root", "x")
        cz = await create_credential_zone(session, "CZ", [cred.id], None)
        czid, cid = cz.id, cred.id
    await _admin(client, session_factory, "er_cz1")
    resp = await client.post(
        f"/credential-zones/{czid}/edit",
        data={"name": "CZ", "credential_ids": [cid], "return_to": "scans"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/scans")
