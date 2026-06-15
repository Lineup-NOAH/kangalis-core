"""Ping taraması (host keşfi) testleri (VI-14)."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.assets import list_assets
from cybersectool.core.findings import count_by_severity
from cybersectool.core.models import Role, ScanType
from cybersectool.core.scans import create_scan
from cybersectool.core.users import create_user
from cybersectool.scanners.network import DiscoveredHost, store_discovery


async def test_store_discovery_populates_inventory(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Keşfedilen ayakta hostlar Asset envanterine yazılır + özet info bulgusu üretilir."""
    async with session_factory() as session:
        scan = await create_scan(session, ScanType.ping, "10.0.0.0/24")
        hosts = [
            DiscoveredHost(ip="10.0.0.1", hostname="router"),
            DiscoveredHost(ip="10.0.0.5", hostname=None),
        ]
        count = await store_discovery(session, scan.id, hosts)
        assert count == 2
        assets = await list_assets(session)
        by_ip = {a.ip: a for a in assets}
        assert {"10.0.0.1", "10.0.0.5"} <= set(by_ip)
        # Ping ile bulunan host AYAKTA işaretlenir (is_up) → hostname'siz olsa da görünür.
        assert by_ip["10.0.0.5"].is_up is True
        from cybersectool.core.assets import list_inventory_assets

        visible = {a.ip for a in await list_inventory_assets(session)}
        assert "10.0.0.5" in visible  # hostname yok ama ping ile ayakta → görünür
        counts = await count_by_severity(session, scan_id=scan.id)
        assert counts.get("info", 0) == 1  # tek özet bulgusu


async def test_store_discovery_empty(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Ayakta host yoksa tek bir 'host bulunamadı' info bulgusu yazılır, varlık eklenmez."""
    async with session_factory() as session:
        scan = await create_scan(session, ScanType.ping, "10.0.0.0/24")
        before = len(await list_assets(session))
        count = await store_discovery(session, scan.id, [])
        assert count == 0
        assert len(await list_assets(session)) == before  # yeni varlık yok
        counts = await count_by_severity(session, scan_id=scan.id)
        assert counts.get("info", 0) == 1


def test_discovery_nmap_options_is_host_discovery_only() -> None:
    """DISCOVERY seçenekleri -sn (port taramasız) içermeli; -sV (servis tespiti) İÇERMEMELİ."""
    from cybersectool.core.scan_policy import DISCOVERY_NMAP_OPTIONS

    assert "-sn" in DISCOVERY_NMAP_OPTIONS  # yalnız host keşfi
    assert "-sV" not in DISCOVERY_NMAP_OPTIONS  # port/servis taraması yok
    assert "-PS" in DISCOVERY_NMAP_OPTIONS  # NAT-dayanıklı TCP SYN probu
    assert "-PA" not in DISCOVERY_NMAP_OPTIONS  # ACK probu YOK (NAT yanlış-pozitif kaynağı)
    # Zamanlama sınırı: NAT'ın 21sn gibi gecikmeli sahte ICMP yanıtlarını eler.
    assert "--max-rtt-timeout" in DISCOVERY_NMAP_OPTIONS


async def _login(
    client: AsyncClient, fac: async_sessionmaker[AsyncSession], username: str, role: Role
) -> None:
    async with fac() as session:
        await create_user(session, username, "pass1234", role=role)
    await client.post(
        "/login", data={"username": username, "password": "pass1234"}, follow_redirects=False
    )


async def test_ping_route_enqueues(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """scan_type=ping → kapsam içi hedefler ping_scan_task'a kuyruğa alınır (303)."""
    from cybersectool import dispatch as dispatch_mod
    from cybersectool.core.models import ScopePolicy

    enqueued: list[tuple[object, ...]] = []
    monkeypatch.setattr(dispatch_mod.ping_scan_task, "delay", lambda *a, **k: enqueued.append(a))
    async with session_factory() as session:
        session.add(
            ScopePolicy(name="s", allowed_cidrs=["10.0.0.0/24"], denied_cidrs=[], is_active=True)
        )
        await session.commit()
    await _login(client, session_factory, "ping_an", Role.analyst)
    resp = await client.post(
        "/scans/start",
        data={"targets": "10.0.0.5", "scan_type": "ping"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert len(enqueued) == 1  # bir ping taraması kuyruğa alındı


async def test_ping_route_scope_denied(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Kapsam dışı hedef → hiçbir tarama başlamaz (400)."""
    from cybersectool import dispatch as dispatch_mod
    from cybersectool.core.models import ScopePolicy

    monkeypatch.setattr(dispatch_mod.ping_scan_task, "delay", lambda *a, **k: None)
    async with session_factory() as session:
        session.add(
            ScopePolicy(name="s", allowed_cidrs=["10.0.0.0/24"], denied_cidrs=[], is_active=True)
        )
        await session.commit()
    await _login(client, session_factory, "ping_an2", Role.analyst)
    resp = await client.post(
        "/scans/start",
        data={"targets": "192.168.99.5", "scan_type": "ping"},
        follow_redirects=False,
    )
    assert resp.status_code == 400  # tümü kapsam dışı


async def test_ping_route_viewer_forbidden(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """viewer ping taraması başlatamaz (403)."""
    await _login(client, session_factory, "ping_v", Role.viewer)
    resp = await client.post(
        "/scans/start",
        data={"targets": "10.0.0.5", "scan_type": "ping"},
        follow_redirects=False,
    )
    assert resp.status_code == 403


async def test_live_view_shows_discovered_hosts(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Canlı (detay) görünüm yanıt veren IP'leri gösterir — rapora girmeden."""
    from cybersectool.core.assets import upsert_asset

    async with session_factory() as session:
        scan = await create_scan(session, ScanType.ping, "10.0.0.0/24")
        sid = scan.id
        await upsert_asset(session, "10.0.0.7", is_up=True)  # yanıt veren host
    await _login(client, session_factory, "live_h", Role.analyst)
    resp = await client.get(f"/scans/{sid}/live")
    assert resp.status_code == 200
    assert "Bulunan Hostlar" in resp.text
    assert "10.0.0.7" in resp.text  # yanıt veren IP canlı görünümde yazılı


async def test_wizard_ping_enqueues(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sihirbaz mode=ping → hedefler ping_scan_task'a kuyruğa alınır (kimlik/kategori yok)."""
    from cybersectool import dispatch as dispatch_mod
    from cybersectool.core.assets import upsert_asset
    from cybersectool.core.models import ScopePolicy
    from cybersectool.core.zones import create_zone

    enqueued: list[tuple[object, ...]] = []
    monkeypatch.setattr(dispatch_mod.ping_scan_task, "delay", lambda *a, **k: enqueued.append(a))
    # Ağ taraması kullanılmamalı (ping yolu) — çağrılırsa testi düşür.
    monkeypatch.setattr(
        dispatch_mod.network_scan_task,
        "delay",
        lambda *a, **k: pytest.fail("ping modunda network_scan çağrılmamalı"),
    )
    async with session_factory() as session:
        session.add(
            ScopePolicy(name="s", allowed_cidrs=["10.0.0.0/24"], denied_cidrs=[], is_active=True)
        )
        await session.commit()
        zone = await create_zone(session, "PZ", ["10.0.0.0/29"])
        asset = await upsert_asset(session, "10.0.0.20")
        zid, aid = zone.id, asset.id
    await _login(client, session_factory, "wiz_ping", Role.analyst)
    resp = await client.post(
        "/scans/wizard",
        data={"zone_ids": [zid], "asset_ids": [aid], "mode": "ping", "name": "Keşif"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    # Birleşik tarama: zone CIDR + tekil IP TEK ping taramasında birleşir (zone=tek tarama).
    assert len(enqueued) == 1
    # Tek görevin hedefi her iki bloğu da içermeli (boşlukla ayrılmış).
    target_arg = enqueued[0][1]
    assert "10.0.0.0/29" in target_arg and "10.0.0.20" in target_arg
