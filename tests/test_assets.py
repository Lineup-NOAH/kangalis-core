"""Asset (varlık) isimlendirme + gösterim adı testleri."""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.assets import (
    create_url_asset,
    get_asset,
    hosts_in_scope,
    is_real_device,
    list_inventory_assets,
    set_asset_name,
    upsert_asset,
    upsert_service,
    web_scan_host_entries,
)
from cybersectool.core.models import Asset, Role, Scan, ScanType
from cybersectool.core.users import create_user


def test_display_name_falls_back_to_url() -> None:
    """URL varlığında (ip=NULL) gösterim adı URL'ye düşer (ad>hostname>url>ip)."""
    a = Asset(url="https://app.kurum.local:8443/portal")
    assert a.display_name == "https://app.kurum.local:8443/portal"
    a.name = "Portal"
    assert a.display_name == "Portal"


async def test_create_url_asset_and_inventory(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Saf URL varlığı: ip=NULL, is_up=True, idempotent; envanterde görünür; sort çökmez."""
    async with session_factory() as session:
        a = await create_url_asset(session, "https://web.kurum.local:8443", name="Web Portal")
        assert a.ip is None
        assert a.url == "https://web.kurum.local:8443"
        assert a.is_up is True
        # Aynı URL tekrar → yeni satır değil (idempotent).
        a2 = await create_url_asset(session, "https://web.kurum.local:8443")
        assert a2.id == a.id
        # Envanterde gerçek-cihaz olarak görünür.
        inv = await list_inventory_assets(session)
        assert any(x.id == a.id for x in inv)
        # URL varlığı (ip=NULL) hosts_in_scope'u ÇÖKERTMEZ (ip-sıralaması) — atlanır.
        hosts = await hosts_in_scope(session, [])
        assert all(h["ip"] != "https://web.kurum.local:8443" for h in hosts)


def test_web_scan_host_entries_uses_target_not_inventory() -> None:
    """Web taraması: taranan URL'in host'u + çözülen IP + şema/port (envanter DEĞİL)."""
    scan = Scan(scan_type=ScanType.web, target="https://site.example", resolved_ip="93.184.216.34")
    entries = web_scan_host_entries([scan])
    assert len(entries) == 1
    h = entries[0]
    assert h["ip"] == "93.184.216.34"
    assert h["name"] == "site.example"
    assert h["is_up"] is True
    svc = h["services"][0]  # type: ignore[index]
    assert svc.port == 443
    assert svc.service_name == "https"


def test_web_scan_host_entries_unresolved_and_http_port() -> None:
    """Çözülen IP yoksa IP '—'; şemasız/HTTP hedef → 80/http."""
    scan = Scan(scan_type=ScanType.web, target="http://10.0.0.9:8080/x", resolved_ip=None)
    h = web_scan_host_entries([scan])[0]
    assert h["ip"] == "—"
    assert h["is_up"] is False
    svc = h["services"][0]  # type: ignore[index]
    assert svc.port == 8080
    assert svc.service_name == "http"


async def test_upsert_asset_stores_name(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as s:
        asset = await upsert_asset(s, "10.0.0.5", name="Muhasebe-PC")
        assert asset.name == "Muhasebe-PC"
        assert asset.display_name == "Muhasebe-PC"


async def test_scan_does_not_wipe_name(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Tarama hostname geçer ama name geçmez → kullanıcı adı korunur."""
    async with session_factory() as s:
        await upsert_asset(s, "10.0.0.5", name="Muhasebe-PC")
        # Tarama akışı: hostname güncellenir, name omitted.
        updated = await upsert_asset(s, "10.0.0.5", hostname="newhost")
        assert updated.name == "Muhasebe-PC"  # korunur
        assert updated.hostname == "newhost"
        assert updated.display_name == "Muhasebe-PC"


async def test_display_name_priority(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as s:
        # name set → name kazanır
        a1 = await upsert_asset(s, "10.0.0.10", hostname="host-a", name="Cihaz")
        assert a1.display_name == "Cihaz"
        # yalnızca hostname → hostname
        a2 = await upsert_asset(s, "10.0.0.11", hostname="host-b")
        assert a2.display_name == "host-b"
        # ne name ne hostname → ip
        a3 = await upsert_asset(s, "10.0.0.12")
        assert a3.display_name == "10.0.0.12"


async def test_add_asset_web_persists_name(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    async with session_factory() as s:
        await create_user(s, "analyst", "secret123", role=Role.analyst)
    login = await client.post(
        "/login",
        data={"username": "analyst", "password": "secret123"},
        follow_redirects=False,
    )
    assert login.status_code == 303
    resp = await client.post(
        "/assets/add",
        data={"ip": "10.0.0.42", "name": "Muhasebe-PC", "hostname": "srv-db-01"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    async with session_factory() as s:
        from cybersectool.core.assets import list_assets

        assets = await list_assets(s)
        assert len(assets) == 1
        asset = await get_asset(s, assets[0].id)
        assert asset is not None
        assert asset.name == "Muhasebe-PC"
        assert asset.display_name == "Muhasebe-PC"


async def test_set_asset_name_core(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """set_asset_name: id ile ad atar; boş ad → None (hostname'e düşer); olmayan id → False."""
    async with session_factory() as s:
        asset = await upsert_asset(s, "10.0.0.5", hostname="srv-1")
        assert await set_asset_name(s, asset.id, "Muhasebe-PC") is True
        got = await get_asset(s, asset.id)
        assert got is not None and got.name == "Muhasebe-PC"
        # Boş/whitespace ad → None → display_name hostname'e düşer.
        assert await set_asset_name(s, asset.id, "   ") is True
        got2 = await get_asset(s, asset.id)
        assert got2 is not None and got2.name is None
        assert got2.display_name == "srv-1"
        # Olmayan id → False.
        assert await set_asset_name(s, 99999, "x") is False


async def test_asset_rename_web(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Web /assets/{id}/name: analyst adı günceller; viewer reddedilir (değişmez)."""
    async with session_factory() as s:
        asset = await upsert_asset(s, "10.0.0.9", hostname="srv-x")
        asset_id = asset.id
        await create_user(s, "analyst", "secret123", role=Role.analyst)
        await create_user(s, "viewer", "secret123", role=Role.viewer)

    # analyst → adı günceller.
    login = await client.post(
        "/login", data={"username": "analyst", "password": "secret123"}, follow_redirects=False
    )
    assert login.status_code == 303
    resp = await client.post(
        f"/assets/{asset_id}/name", data={"name": "Patron-Laptop"}, follow_redirects=False
    )
    assert resp.status_code == 303
    async with session_factory() as s:
        got = await get_asset(s, asset_id)
        assert got is not None and got.name == "Patron-Laptop"

    # viewer → reddedilir, ad değişmez.
    vlogin = await client.post(
        "/login", data={"username": "viewer", "password": "secret123"}, follow_redirects=False
    )
    assert vlogin.status_code == 303
    vresp = await client.post(
        f"/assets/{asset_id}/name", data={"name": "Hacker"}, follow_redirects=False
    )
    assert vresp.status_code == 303  # /assets'e geri yönlendirir, işlem yapmaz
    async with session_factory() as s:
        got2 = await get_asset(s, asset_id)
        assert got2 is not None and got2.name == "Patron-Laptop"  # değişmedi


def test_is_real_device_visibility() -> None:
    """is_real_device: servisli/adlı/hostname'li görünür; çıplak IP gizli; kendi altyapı gizli."""
    from cybersectool.core.models import Asset

    bare = Asset(id=1, ip="10.0.0.1")
    named = Asset(id=2, ip="10.0.0.2", name="Patron-PC")
    hosted = Asset(id=3, ip="10.0.0.3", hostname="srv-x")
    served = Asset(id=4, ip="10.0.0.4")
    infra = Asset(id=5, ip="172.18.0.2", hostname="db")
    # Ping/taramada AYAKTA doğrulanmış çıplak IP (servis/ad/hostname yok) → artık görünür.
    up_bare = Asset(id=6, ip="10.0.0.6", is_up=True)
    # Kendi altyapısı is_up olsa bile gizli.
    infra_up = Asset(id=7, ip="172.18.0.2", is_up=True)
    svc_ids = {4}
    infra_ips = {"172.18.0.2"}
    assert is_real_device(bare, asset_ids_with_service=svc_ids, infra_ips=infra_ips) is False
    assert is_real_device(named, asset_ids_with_service=svc_ids, infra_ips=infra_ips) is True
    assert is_real_device(hosted, asset_ids_with_service=svc_ids, infra_ips=infra_ips) is True
    assert is_real_device(served, asset_ids_with_service=svc_ids, infra_ips=infra_ips) is True
    assert is_real_device(up_bare, asset_ids_with_service=svc_ids, infra_ips=infra_ips) is True
    # Kendi altyapı IP'si hostname'li/is_up bile olsa gizli.
    assert is_real_device(infra, asset_ids_with_service=svc_ids, infra_ips=infra_ips) is False
    assert is_real_device(infra_up, asset_ids_with_service=svc_ids, infra_ips=infra_ips) is False


async def test_list_inventory_assets_filters_junk(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """list_inventory_assets: çıplak/boş IP gizlenir; servisli/adlı/hostname'li görünür."""
    async with session_factory() as s:
        bare = await upsert_asset(s, "10.0.0.1")  # çıplak, yanıt yok → gizli
        await upsert_asset(s, "10.0.0.2", name="Patron-PC")  # adlı → görünür
        await upsert_asset(s, "10.0.0.3", hostname="srv-x")  # hostname → görünür
        served = await upsert_asset(s, "10.0.0.4")  # servisli → görünür
        await upsert_service(s, served.id, 22, service_name="ssh")
        await upsert_asset(s, "10.0.0.5", is_up=True)  # ping ile ayakta → görünür

        visible = await list_inventory_assets(s)
        visible_ips = {a.ip for a in visible}
        assert "10.0.0.1" not in visible_ips  # çıplak (is_up=False) gizli
        assert visible_ips == {"10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"}

        # show_all → hepsi (çıplak dahil).
        all_assets = await list_inventory_assets(s, show_all=True)
        assert bare.ip in {a.ip for a in all_assets}
        assert len(all_assets) == 5
