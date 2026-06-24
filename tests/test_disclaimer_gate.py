"""Sorumluluk reddi (DISCLAIMER.md) kapısı — uygulama-içi kabul akışı.

Bu testler kapıyı GERÇEK haliyle sınar: ``pytestmark = disclaimer_gate`` ile conftest'teki
genel bypass atlanır. Kapsam: girişte yönlendirme + ``/scans*`` engeli (GET/POST) + kabul →
zaman damgası + denetim kaydı + erişimin açılması; oturumsuz isteklerin etkilenmemesi.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.models import AuditLog, Role, User
from cybersectool.core.users import create_user

pytestmark = pytest.mark.disclaimer_gate


async def _login(
    client: AsyncClient,
    factory: async_sessionmaker[AsyncSession],
    username: str = "adm_disc",
    role: Role = Role.admin,
) -> None:
    async with factory() as s:
        await create_user(s, username, "pass1234", role=role)
    await client.post(
        "/login", data={"username": username, "password": "pass1234"}, follow_redirects=False
    )


async def test_login_redirects_to_disclaimer_when_not_accepted(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    async with session_factory() as s:
        await create_user(s, "adm_disc", "pass1234", role=Role.admin)
    resp = await client.post(
        "/login", data={"username": "adm_disc", "password": "pass1234"}, follow_redirects=False
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/disclaimer"


async def test_scans_page_blocked_until_accepted(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory)
    resp = await client.get("/scans", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/disclaimer"


async def test_scan_start_post_forbidden_until_accepted(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Kabul edilmeden tarama BAŞLATMA (POST /scans*) 403 (kapı route'tan önce çalışır)."""
    await _login(client, session_factory)
    resp = await client.post("/scans/start", data={"target": "10.0.0.1"}, follow_redirects=False)
    assert resp.status_code == 403


async def test_disclaimer_page_renders_checkbox(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory)
    resp = await client.get("/disclaimer")
    assert resp.status_code == 200
    assert 'name="acknowledge"' in resp.text


async def test_accept_unlocks_scanning_and_audits(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory)
    accept = await client.post(
        "/disclaimer/accept", data={"acknowledge": "on"}, follow_redirects=False
    )
    assert accept.status_code == 303
    assert accept.headers["location"] == "/"
    # Kabul sonrası /scans erişilebilir (kapı geçer).
    page = await client.get("/scans", follow_redirects=False)
    assert page.status_code == 200
    # DB'de zaman damgası dolu + denetim olayı kaydedildi.
    async with session_factory() as s:
        user = (await s.execute(select(User).where(User.username == "adm_disc"))).scalar_one()
        assert user.disclaimer_accepted_at is not None
        actions = (await s.execute(select(AuditLog.action))).scalars().all()
        assert "disclaimer_accepted" in actions


async def test_accept_without_checkbox_redirects_back(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory)
    resp = await client.post("/disclaimer/accept", data={}, follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/disclaimer"
    # Onay kutusu işaretlenmediği için tarama hâlâ engelli.
    page = await client.get("/scans", follow_redirects=False)
    assert page.status_code == 303
    assert page.headers["location"] == "/disclaimer"


async def test_anonymous_scans_not_gated_to_disclaimer(client: AsyncClient) -> None:
    """Oturumsuz istekte kapı devreye girmez → route normal /login yönlendirmesini yapar."""
    resp = await client.get("/scans", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"


# --- /scans önekinde OLMAYAN tarama/denetim uçları: require_disclaimer_accepted dependency'si
# bunları da kapatır (middleware kapsamı dışı). Hepsi aynı dependency'yi kullanır; 3 temsilci. ---


async def test_api_sca_forbidden_until_accepted(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory)
    resp = await client.post(
        "/sca", json={"ecosystem": "PyPI", "content": "flask==1.0"}, follow_redirects=False
    )
    assert resp.status_code == 403
    assert "Sorumluluk" in resp.json()["detail"]


async def test_api_hardening_forbidden_until_accepted(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory)
    resp = await client.post(
        "/hardening",
        json={"host": "10.0.0.1", "username": "u", "password": "p"},
        follow_redirects=False,
    )
    assert resp.status_code == 403
    assert "Sorumluluk" in resp.json()["detail"]


async def test_api_demo_scan_forbidden_until_accepted(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory)
    resp = await client.post("/admin/demo-scan", follow_redirects=False)
    assert resp.status_code == 403
    assert "Sorumluluk" in resp.json()["detail"]
