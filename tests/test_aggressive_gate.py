"""Agresif tarama kill-switch'i tüm yollarda tutarlı uygulanır (bug #1).

Bug-avı #1: /scans/start (hızlı) + /scans/wizard + web-DAST yolları global
ALLOW_AGGRESSIVE_SCANS kilidini atlıyordu (zone/API uyguluyordu). Artık hepsi
ensure_mode_allowed çağırır → kilit kapalıyken admin + ack olsa bile 403.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.config import settings
from cybersectool.core.models import Role, ScopePolicy
from cybersectool.core.users import create_user


async def _admin(client: AsyncClient, fac: async_sessionmaker[AsyncSession], username: str) -> None:
    async with fac() as session:
        await create_user(session, username, "pass1234", role=Role.admin)
        session.add(
            ScopePolicy(name="s", allowed_cidrs=["10.0.0.0/24"], denied_cidrs=[], is_active=True)
        )
        await session.commit()
    await client.post(
        "/login", data={"username": username, "password": "pass1234"}, follow_redirects=False
    )


async def test_quick_aggressive_blocked_when_killswitch_off(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """ALLOW_AGGRESSIVE_SCANS kapalıyken hızlı agresif CVE (admin+ack) → 403."""
    await _admin(client, session_factory, "killadm")
    settings.allow_aggressive_scans = False  # autouse fixture sonradan geri yükler
    resp = await client.post(
        "/scans/start",
        data={"targets": "10.0.0.5", "mode": "cve_aggressive", "aggressive_ack": "on"},
        follow_redirects=False,
    )
    assert resp.status_code == 403


async def test_wizard_aggressive_blocked_when_killswitch_off(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """ALLOW_AGGRESSIVE_SCANS kapalıyken sihirbaz agresif CVE (admin+ack) → 403."""
    from cybersectool.core.assets import upsert_asset

    await _admin(client, session_factory, "killwiz")
    async with session_factory() as session:  # sihirbaz hedefi asset_ids ile alır
        asset = await upsert_asset(session, "10.0.0.5")
        aid = asset.id
    settings.allow_aggressive_scans = False
    resp = await client.post(
        "/scans/wizard",
        data={"asset_ids": [aid], "mode": "cve_aggressive", "aggressive_ack": "on"},
        follow_redirects=False,
    )
    assert resp.status_code == 403


async def test_quick_aggressive_allowed_when_killswitch_on(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Kilit açık (autouse fixture) + admin + ack → 303 (agresif çalışır)."""
    from cybersectool import dispatch as dispatch_mod

    monkeypatch.setattr(dispatch_mod.network_scan_task, "delay", lambda *a, **k: None)
    await _admin(client, session_factory, "killon")
    # settings.allow_aggressive_scans autouse fixture ile zaten True.
    resp = await client.post(
        "/scans/start",
        data={"targets": "10.0.0.5", "mode": "cve_aggressive", "aggressive_ack": "on"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
