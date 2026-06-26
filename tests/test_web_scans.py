"""Tarama/varlık web sayfaları testleri."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.models import Role
from cybersectool.core.users import create_user


async def _login(
    client: AsyncClient,
    factory: async_sessionmaker[AsyncSession],
    username: str,
    role: Role = Role.analyst,
) -> None:
    async with factory() as session:
        await create_user(session, username, "pass1234", role=role)
    await client.post("/auth/login", json={"username": username, "password": "pass1234"})


async def test_scans_page_renders(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "an1")
    resp = await client.get("/scans")
    assert resp.status_code == 200
    assert "Tarama Başlat" in resp.text


async def test_scans_exploit_mode_gated(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sömürme (exploit) modu YALNIZ eklenti+lisans (exploit_unlocked) + admin için forma düşer."""
    # Varsayılan: eklenti/lisans yok → exploit_unlocked False → seçenek GÖRÜNMEZ.
    await _login(client, session_factory, "exadmin", Role.admin)
    resp = await client.get("/scans")
    assert resp.status_code == 200
    assert 'value="exploit"' not in resp.text

    # Eklenti kurulu + lisanslı (exploit_unlocked True) → seçenek admin formuna düşer.
    async def _unlocked(_session: object) -> bool:
        return True

    monkeypatch.setattr("cybersectool.web.routes.exploit_unlocked", _unlocked)
    resp2 = await client.get("/scans")
    assert 'value="exploit"' in resp2.text

    # Admin-only: kilit açık olsa bile analist görmez.
    await _login(client, session_factory, "exanalyst", Role.analyst)
    resp3 = await client.get("/scans")
    assert 'value="exploit"' not in resp3.text


async def test_scans_redirects_anonymous(client: AsyncClient) -> None:
    resp = await client.get("/scans", follow_redirects=False)
    assert resp.status_code == 303


async def test_api_hardening_scope_enforced(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """API /hardening kapsam dışı host'u reddeder (scope guard — admin dahi geçemez)."""
    await _login(client, session_factory, "hsec", Role.admin)
    resp = await client.post(
        "/hardening", json={"host": "8.8.8.8", "username": "u", "password": "p"}
    )
    assert resp.status_code == 403  # scope politikası yok → default-deny


async def test_api_credentialed_scope_enforced(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """API /scans/credentialed kapsam dışı host'u reddeder."""
    await _login(client, session_factory, "csec", Role.admin)
    resp = await client.post(
        "/scans/credentialed", json={"host": "8.8.8.8", "username": "u", "password": "p"}
    )
    assert resp.status_code == 403


async def test_lang_open_redirect_blocked(client: AsyncClient) -> None:
    """Dış-köken referer açık yönlendirmeye değil ana sayfaya döner; aynı-köken korunur."""
    ext = await client.get(
        "/lang/en", headers={"referer": "https://evil.example/phish"}, follow_redirects=False
    )
    assert ext.status_code == 303
    assert ext.headers["location"] == "/"
    same = await client.get(
        "/lang/tr", headers={"referer": "http://test/scans"}, follow_redirects=False
    )
    assert same.headers["location"] == "http://test/scans"


async def test_security_headers_present(client: AsyncClient) -> None:
    resp = await client.get("/health")
    assert resp.headers.get("x-frame-options") == "DENY"
    assert resp.headers.get("x-content-type-options") == "nosniff"
    assert "referrer-policy" in resp.headers


async def test_assets_page_renders(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "an2")
    resp = await client.get("/assets")
    assert resp.status_code == 200
    assert "Varlıklar" in resp.text


async def test_start_scan_scope_error(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "an3", Role.analyst)
    # Tanımlı scope politikası yok → tüm hedefler kapsam dışı atlanır → 400 (Celery'ye gitmeden)
    resp = await client.post(
        "/scans/start", data={"targets": "10.0.0.0/24"}, follow_redirects=False
    )
    assert resp.status_code == 400
    assert "kapsam" in resp.text.lower()


async def test_start_scan_viewer_forbidden(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "vi1", Role.viewer)
    resp = await client.post(
        "/scans/start", data={"targets": "10.0.0.0/24"}, follow_redirects=False
    )
    assert resp.status_code == 403


async def test_unified_scan_multi_target(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Birleşik form: virgülle ayrılmış çok hedef; kapsam içi olanlar başlatılır."""
    from cybersectool import dispatch as dispatch_mod
    from cybersectool.core.models import ScopePolicy

    monkeypatch.setattr(dispatch_mod.network_scan_task, "delay", lambda *a, **k: None)
    async with session_factory() as session:
        session.add(
            ScopePolicy(name="s", allowed_cidrs=["10.0.0.0/24"], denied_cidrs=[], is_active=True)
        )
        await session.commit()
    await _login(client, session_factory, "qa1", Role.analyst)
    # Virgülle ayrılmış 3 hedef: 2'si kapsam içi, 1'i dışı
    resp = await client.post(
        "/scans/start",
        data={"targets": "10.0.0.5, 10.0.0.6, 192.168.99.1", "mode": "safe"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "2" in resp.headers["location"]  # 2 hedef başlatıldı


async def test_unified_scan_empty_targets(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "qa2", Role.analyst)
    resp = await client.post(
        "/scans/start", data={"targets": "  ,  ", "mode": "safe"}, follow_redirects=False
    )
    assert resp.status_code == 400


async def test_unified_scan_viewer_forbidden(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "qv1", Role.viewer)
    resp = await client.post(
        "/scans/start", data={"targets": "10.0.0.5", "mode": "safe"}, follow_redirects=False
    )
    assert resp.status_code == 403


# --- VI-11: SCA yapıştır + dosya yükle ---
async def test_sca_paste_content(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SCA: manifest yapıştırma → 303 + task (ecosystem, content) ile çağrılır."""
    from cybersectool.web import routes as routes_mod

    calls: list[tuple[object, ...]] = []
    monkeypatch.setattr(routes_mod.sca_scan_task, "delay", lambda *a, **k: calls.append(a))
    await _login(client, session_factory, "sca1", Role.analyst)
    resp = await client.post(
        "/scans/sca",
        data={"ecosystem": "PyPI", "content": "django==2.2.0\nrequests==2.6.0"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert len(calls) == 1
    assert calls[0][1] == "PyPI"
    assert "django" in str(calls[0][2])


async def test_sca_file_upload_autodetect(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SCA dosya yükleme: içerik dosyadan okunur + ekosistem dosya adından sezilir."""
    from cybersectool.web import routes as routes_mod

    calls: list[tuple[object, ...]] = []
    monkeypatch.setattr(routes_mod.sca_scan_task, "delay", lambda *a, **k: calls.append(a))
    await _login(client, session_factory, "sca2", Role.analyst)
    # ecosystem 'npm' gönderilse de requirements.txt → PyPI'ye otomatik düzelir.
    resp = await client.post(
        "/scans/sca",
        data={"ecosystem": "npm"},
        files={"manifest_file": ("requirements.txt", b"flask==1.0.0\n", "text/plain")},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert len(calls) == 1
    assert calls[0][1] == "PyPI"  # dosya adından sezildi
    assert "flask" in str(calls[0][2])


async def test_sca_empty_both_rejected(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Ne içerik ne dosya → 400."""
    await _login(client, session_factory, "sca3", Role.analyst)
    resp = await client.post(
        "/scans/sca", data={"ecosystem": "PyPI", "content": "   "}, follow_redirects=False
    )
    assert resp.status_code == 400


# --- VI-2: web DAST agresif kilidi ---
async def test_web_scan_safe_dispatches(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Güvenli web taraması → 303 + task mode='safe' ile çağrılır (pasif derinlik)."""
    from cybersectool.web import routes as routes_mod

    calls: list[tuple[object, ...]] = []
    monkeypatch.setattr(routes_mod.web_scan_task, "delay", lambda *a, **k: calls.append(a))
    await _login(client, session_factory, "web1", Role.analyst)
    resp = await client.post(
        "/scans/start",
        data={"targets": "http://example.test", "scan_type": "web", "mode": "safe"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert len(calls) == 1
    assert calls[0][2] == "safe"


async def test_web_scan_aggressive_requires_admin(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Agresif web (DAST) → analyst reddedilir (yalnız admin)."""
    await _login(client, session_factory, "web2", Role.analyst)
    resp = await client.post(
        "/scans/start",
        data={
            "targets": "http://example.test",
            "scan_type": "web",
            "mode": "aggressive",
            "aggressive_ack": "1",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 403


async def test_web_scan_aggressive_requires_ack(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Agresif web (DAST), admin ama ack yok → 400."""
    await _login(client, session_factory, "web3", Role.admin)
    resp = await client.post(
        "/scans/start",
        data={"targets": "http://example.test", "scan_type": "web", "mode": "aggressive"},
        follow_redirects=False,
    )
    assert resp.status_code == 400


async def test_web_scan_aggressive_ok(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Agresif web (DAST), admin + ack → 303 + task mode='aggressive'."""
    from cybersectool.web import routes as routes_mod

    calls: list[tuple[object, ...]] = []
    monkeypatch.setattr(routes_mod.web_scan_task, "delay", lambda *a, **k: calls.append(a))
    await _login(client, session_factory, "web4", Role.admin)
    resp = await client.post(
        "/scans/start",
        data={
            "targets": "http://example.test",
            "scan_type": "web",
            "mode": "aggressive",
            "aggressive_ack": "1",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert calls[0][2] == "aggressive"


async def test_unified_scan_web_multi(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Web türü: her hedef bir URL; scope guard'a takılmaz, her biri kuyruğa alınır."""
    from cybersectool.web import routes as routes_mod

    enqueued: list[tuple[object, ...]] = []
    monkeypatch.setattr(routes_mod.web_scan_task, "delay", lambda *a, **k: enqueued.append(a))
    await _login(client, session_factory, "qa3", Role.analyst)
    resp = await client.post(
        "/scans/start",
        data={"targets": "https://a.example\nhttps://b.example", "scan_type": "web"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert len(enqueued) == 2  # iki web taraması kuyruğa alındı


# --- Dış (public internet) web hedefi — admin + açık onayla iç-ağ kapsamı atlanır ---
async def test_web_scan_external_admin_sets_flag(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Admin + dış-hedef kutucuğu → 303; scan.allow_external=True ve görev kuyruğa alınır."""
    from cybersectool.core.scans import list_scans
    from cybersectool.web import routes as routes_mod

    calls: list[tuple[object, ...]] = []
    monkeypatch.setattr(routes_mod.web_scan_task, "delay", lambda *a, **k: calls.append(a))
    await _login(client, session_factory, "wext1", Role.admin)
    resp = await client.post(
        "/scans/start",
        data={
            "targets": "https://kare-webtoon.vercel.app",
            "scan_type": "web",
            "mode": "safe",
            "web_external": "on",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert len(calls) == 1
    async with session_factory() as session:
        scans = await list_scans(session)
    assert len(scans) == 1
    assert scans[0].allow_external is True


async def test_web_scan_external_requires_admin(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Analyst + dış-hedef kutucuğu → 403 (yalnız admin dış hedefi açabilir)."""
    await _login(client, session_factory, "wext2", Role.analyst)
    resp = await client.post(
        "/scans/start",
        data={
            "targets": "https://kare-webtoon.vercel.app",
            "scan_type": "web",
            "mode": "safe",
            "web_external": "on",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 403


async def test_web_scan_dirscan_sets_flag(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Web modunda 'Dizin taraması' kutucuğu → scan.dir_scan=True (analyst de açabilir)."""
    from cybersectool.core.scans import list_scans
    from cybersectool.web import routes as routes_mod

    monkeypatch.setattr(routes_mod.web_scan_task, "delay", lambda *a, **k: None)
    await _login(client, session_factory, "wdir1", Role.analyst)
    resp = await client.post(
        "/scans/start",
        data={"targets": "http://example.test", "mode": "web", "web_dirscan": "on"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    async with session_factory() as session:
        scans = await list_scans(session)
    assert len(scans) == 1
    assert scans[0].dir_scan is True
    assert scans[0].wordlist_id is None  # liste seçilmedi → yerleşik (None)


async def test_web_scan_dirscan_uses_selected_wordlist(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dizin taraması + özel kelime listesi seçilince scan.wordlist_id'ye yazılır."""
    from cybersectool.core.models import WordlistKind
    from cybersectool.core.scans import list_scans
    from cybersectool.core.wordlists import create_wordlist
    from cybersectool.web import routes as routes_mod

    monkeypatch.setattr(routes_mod.web_scan_task, "delay", lambda *a, **k: None)
    await _login(client, session_factory, "wdir2", Role.admin)
    async with session_factory() as session:
        wl = await create_wordlist(session, "ozel-web", WordlistKind.web_dir, ["panel", "api"])
        wl_id = wl.id
    resp = await client.post(
        "/scans/start",
        data={
            "targets": "http://example.test",
            "mode": "web",
            "web_dirscan": "on",
            "web_wordlist_id": str(wl_id),
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    async with session_factory() as session:
        scans = await list_scans(session)
    assert len(scans) == 1
    assert scans[0].dir_scan is True
    assert scans[0].wordlist_id == wl_id


async def test_web_scan_wordlist_ignored_without_dirscan(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dizin taraması kapalıyken kelime listesi seçimi yok sayılır (wordlist_id None)."""
    from cybersectool.core.models import WordlistKind
    from cybersectool.core.scans import list_scans
    from cybersectool.core.wordlists import create_wordlist
    from cybersectool.web import routes as routes_mod

    monkeypatch.setattr(routes_mod.web_scan_task, "delay", lambda *a, **k: None)
    await _login(client, session_factory, "wdir3", Role.admin)
    async with session_factory() as session:
        wl = await create_wordlist(session, "ignore-web", WordlistKind.web_dir, ["x"])
        wl_id = wl.id
    resp = await client.post(
        "/scans/start",
        data={"targets": "http://example.test", "mode": "web", "web_wordlist_id": str(wl_id)},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    async with session_factory() as session:
        scans = await list_scans(session)
    assert scans[0].dir_scan is False
    assert scans[0].wordlist_id is None


async def test_web_scan_external_off_by_default(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Kutucuk yoksa scan.allow_external=False (normal iç-ağ scope guard'ı geçerli)."""
    from cybersectool.core.scans import list_scans
    from cybersectool.web import routes as routes_mod

    monkeypatch.setattr(routes_mod.web_scan_task, "delay", lambda *a, **k: None)
    await _login(client, session_factory, "wext3", Role.admin)
    resp = await client.post(
        "/scans/start",
        data={"targets": "http://example.test", "scan_type": "web", "mode": "safe"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    async with session_factory() as session:
        scans = await list_scans(session)
    assert scans[0].allow_external is False


async def test_bulk_zones_scan_web(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Toplu zone taraması: birden çok IP zone seçilir, hepsi taranır."""
    from cybersectool import dispatch as dispatch_mod
    from cybersectool.core.models import ScopePolicy
    from cybersectool.core.zones import create_zone

    monkeypatch.setattr(dispatch_mod.network_scan_task, "delay", lambda *a, **k: None)
    async with session_factory() as session:
        session.add(
            ScopePolicy(name="s", allowed_cidrs=["10.0.0.0/24"], denied_cidrs=[], is_active=True)
        )
        await session.commit()
        z1 = await create_zone(session, "Z1", ["10.0.0.0/24"])
        z2 = await create_zone(session, "Z2", ["10.0.0.0/25"])
        ids = [z1.id, z2.id]
    await _login(client, session_factory, "bz1", Role.analyst)
    resp = await client.post(
        "/scans/zones",
        data={"zone_ids": ids, "kind": "safe"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "2+zone" in resp.headers["location"] or "2%20zone" in resp.headers["location"]


async def test_bulk_zones_empty(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "bz2", Role.analyst)
    resp = await client.post("/scans/zones", data={"kind": "safe"}, follow_redirects=False)
    assert resp.status_code == 400


async def test_bulk_zones_viewer_forbidden(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "bz3", Role.viewer)
    resp = await client.post(
        "/scans/zones", data={"zone_ids": [1], "kind": "safe"}, follow_redirects=False
    )
    assert resp.status_code == 403


async def test_wizard_network_targets(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sihirbaz: IP zone + tekil IP varlığı hedefleriyle ağ taraması."""
    from cybersectool import dispatch as dispatch_mod
    from cybersectool.core.assets import upsert_asset
    from cybersectool.core.models import ScopePolicy
    from cybersectool.core.zones import create_zone

    monkeypatch.setattr(dispatch_mod.network_scan_task, "delay", lambda *a, **k: None)
    async with session_factory() as session:
        session.add(
            ScopePolicy(name="s", allowed_cidrs=["10.0.0.0/24"], denied_cidrs=[], is_active=True)
        )
        await session.commit()
        zone = await create_zone(session, "Z", ["10.0.0.0/24"])
        asset = await upsert_asset(session, "10.0.0.5")
        zid, aid = zone.id, asset.id
    await _login(client, session_factory, "wz1", Role.analyst)
    resp = await client.post(
        "/scans/wizard",
        data={"zone_ids": [zid], "asset_ids": [aid], "mode": "safe", "name": "Test taraması"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "2" in resp.headers["location"]  # 2 hedef (blok) başlatıldı
    # Tek isimli tarama işi (ScanBatch) oluştu; zone CIDR + tekil IP TEK taramada birleşti.
    async with session_factory() as session:
        from cybersectool.core.scan_batches import list_batches
        from cybersectool.core.scans import list_scans

        batches = await list_batches(session)
        assert batches and batches[0].name == "Test taraması"
        scans = await list_scans(session)
        assert len(scans) == 1  # birleşik tarama: N hedef → 1 tarama (taramalara bölmez)
        assert scans[0].batch_id == batches[0].id
        assert "10.0.0.0/24" in scans[0].target and "10.0.0.5" in scans[0].target


async def test_wizard_schedule_creates_schedule(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sihirbazda 'Zamanla' seçilince hemen başlamaz; batch-şablonu ScheduledScan oluşur."""
    from cybersectool import dispatch as dispatch_mod
    from cybersectool.core.assets import upsert_asset
    from cybersectool.core.models import ScopePolicy
    from cybersectool.core.scans import list_scans
    from cybersectool.core.schedules import list_schedules

    monkeypatch.setattr(dispatch_mod.network_scan_task, "delay", lambda *a, **k: None)
    async with session_factory() as session:
        session.add(
            ScopePolicy(name="s", allowed_cidrs=["10.0.0.0/24"], denied_cidrs=[], is_active=True)
        )
        await session.commit()
        asset = await upsert_asset(session, "10.0.0.5")
        aid = asset.id
    await _login(client, session_factory, "wsch", Role.analyst)
    resp = await client.post(
        "/scans/wizard",
        data={
            "asset_ids": [aid],
            "mode": "safe",
            "name": "Haftalık iş",
            "sched_mode": "schedule",
            "sched_period": "weekly",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "zamanland" in resp.headers["location"]
    async with session_factory() as session:
        scheds = await list_schedules(session)
        assert scheds and scheds[0].name == "Haftalık iş"
        assert scheds[0].asset_ids == [aid]
        assert scheds[0].period == "weekly"
        assert await list_scans(session) == []  # hemen başlatılmadı


async def test_wizard_empty_targets(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "wz2", Role.analyst)
    resp = await client.post("/scans/wizard", data={"mode": "safe"}, follow_redirects=False)
    assert resp.status_code == 400


async def test_wizard_viewer_forbidden(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "wz3", Role.viewer)
    resp = await client.post(
        "/scans/wizard", data={"asset_ids": [1], "mode": "safe"}, follow_redirects=False
    )
    assert resp.status_code == 403


async def test_wizard_aggressive_requires_ack(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Agresif sihirbaz: 'kabul ediyorum' tiki olmadan 400; tikle 303 (env kilidi YERİNE)."""
    from cybersectool import dispatch as dispatch_mod
    from cybersectool.core.assets import upsert_asset
    from cybersectool.core.models import ScopePolicy

    monkeypatch.setattr(dispatch_mod.network_scan_task, "delay", lambda *a, **k: None)
    async with session_factory() as session:
        session.add(
            ScopePolicy(name="s", allowed_cidrs=["10.0.0.0/24"], denied_cidrs=[], is_active=True)
        )
        await session.commit()
        asset = await upsert_asset(session, "10.0.0.5")
        aid = asset.id
    await _login(client, session_factory, "wz4", Role.admin)
    # onay tiki yok → 400
    no_ack = await client.post(
        "/scans/wizard",
        data={"asset_ids": [aid], "mode": "aggressive"},
        follow_redirects=False,
    )
    assert no_ack.status_code == 400
    # onay tiki var → 303 (ALLOW_AGGRESSIVE_SCANS kapalı olsa bile çalışır)
    with_ack = await client.post(
        "/scans/wizard",
        data={"asset_ids": [aid], "mode": "aggressive", "aggressive_ack": "on"},
        follow_redirects=False,
    )
    assert with_ack.status_code == 303


async def _scope_and_login(
    client: AsyncClient,
    factory: async_sessionmaker[AsyncSession],
    username: str,
    role: Role = Role.analyst,
) -> None:
    from cybersectool.core.models import ScopePolicy

    async with factory() as session:
        session.add(
            ScopePolicy(name="s", allowed_cidrs=["10.0.0.0/24"], denied_cidrs=[], is_active=True)
        )
        await session.commit()
    await _login(client, factory, username, role)


async def test_quick_scan_vuln_type(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hızlı tarama 'zafiyet' türü: ScanType.vuln kaydı + isimli batch oluşur."""
    from cybersectool import dispatch as dispatch_mod
    from cybersectool.core.models import ScanType
    from cybersectool.core.scan_batches import list_batches
    from cybersectool.core.scans import list_scans

    monkeypatch.setattr(dispatch_mod.network_scan_task, "delay", lambda *a, **k: None)
    await _scope_and_login(client, session_factory, "qvuln")
    resp = await client.post(
        "/scans/start",
        data={"targets": "10.0.0.5", "scan_type": "vuln", "name": "Zafiyet işi"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    async with session_factory() as session:
        scans = await list_scans(session)
        assert scans and scans[0].scan_type == ScanType.vuln
        batches = await list_batches(session)
        assert batches and batches[0].name == "Zafiyet işi"
        assert all(s.batch_id == batches[0].id for s in scans)


async def test_quick_scan_custom_ports(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Elle port seçimi temizlenip tarama kaydına yazılır."""
    from cybersectool import dispatch as dispatch_mod
    from cybersectool.core.scans import list_scans

    monkeypatch.setattr(dispatch_mod.network_scan_task, "delay", lambda *a, **k: None)
    await _scope_and_login(client, session_factory, "qports")
    resp = await client.post(
        "/scans/start",
        data={"targets": "10.0.0.5", "ports": "custom", "ports_custom": "80,443, 8080"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    async with session_factory() as session:
        scans = await list_scans(session)
        assert scans and scans[0].ports == "80,443,8080"


async def test_quick_scan_auto_name(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """İsim verilmezse 'Hızlı tarama 1' otomatik numaralanır."""
    from cybersectool import dispatch as dispatch_mod
    from cybersectool.core.scan_batches import list_batches

    monkeypatch.setattr(dispatch_mod.network_scan_task, "delay", lambda *a, **k: None)
    await _scope_and_login(client, session_factory, "qauto")
    resp = await client.post("/scans/start", data={"targets": "10.0.0.5"}, follow_redirects=False)
    assert resp.status_code == 303
    async with session_factory() as session:
        batches = await list_batches(session)
        assert batches and batches[0].name == "Hızlı tarama 1"


async def test_quick_scan_aggressive_requires_ack(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hızlı tarama agresif: ack olmadan 400; ack ile 303 (env kilidi YERİNE)."""
    from cybersectool import dispatch as dispatch_mod

    monkeypatch.setattr(dispatch_mod.network_scan_task, "delay", lambda *a, **k: None)
    await _scope_and_login(client, session_factory, "qaggr", Role.admin)
    no_ack = await client.post(
        "/scans/start",
        data={"targets": "10.0.0.5", "mode": "aggressive"},
        follow_redirects=False,
    )
    assert no_ack.status_code == 400
    with_ack = await client.post(
        "/scans/start",
        data={"targets": "10.0.0.5", "mode": "aggressive", "aggressive_ack": "on"},
        follow_redirects=False,
    )
    assert with_ack.status_code == 303


async def test_quick_scan_aggressive_analyst_forbidden(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Analist agresif mod isteyemez (admin değil) → 403."""
    await _scope_and_login(client, session_factory, "qaggr2", Role.analyst)
    resp = await client.post(
        "/scans/start",
        data={"targets": "10.0.0.5", "mode": "aggressive", "aggressive_ack": "on"},
        follow_redirects=False,
    )
    assert resp.status_code == 403


async def test_add_asset_web(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Envanter: analist tekil IP varlığı ekleyebilir; /assets listesinde görünür (VI-10)."""
    await _login(client, session_factory, "iv1", Role.analyst)
    resp = await client.post(
        "/assets/add", data={"ip": "10.0.0.42", "hostname": "srv-db"}, follow_redirects=False
    )
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/assets")
    page = await client.get("/assets")
    assert "10.0.0.42" in page.text
    assert "srv-db" in page.text


async def test_add_asset_invalid_ip(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Geçersiz IP → 303 (hata query param ile /assets'e döner), varlık oluşmaz."""
    await _login(client, session_factory, "iv2", Role.analyst)
    resp = await client.post("/assets/add", data={"ip": "not-an-ip"}, follow_redirects=False)
    assert resp.status_code == 303
    assert "err=" in resp.headers["location"]
    async with session_factory() as s:
        from cybersectool.core.assets import list_assets

        assert await list_assets(s) == []


async def test_add_asset_viewer_forbidden(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Viewer ekleyemez → 303 (no-op redirect), varlık oluşmaz."""
    await _login(client, session_factory, "iv3", Role.viewer)
    resp = await client.post("/assets/add", data={"ip": "10.0.0.7"}, follow_redirects=False)
    assert resp.status_code == 303
    async with session_factory() as s:
        from cybersectool.core.assets import list_assets

        assert await list_assets(s) == []


async def test_zone_edit_web(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Admin birleşik edit ekranından zone'u günceller (ad + IP blokları)."""
    from cybersectool.core.zones import create_zone, get_zone

    async with session_factory() as session:
        z = await create_zone(session, "EditZone", ["10.0.0.0/24"])
        zid = z.id
    await _login(client, session_factory, "ze1", Role.admin)
    page = await client.get(f"/zones/{zid}/edit")
    assert page.status_code == 200
    assert "EditZone" in page.text
    resp = await client.post(
        f"/zones/{zid}/edit",
        data={"name": "EditZone2", "cidrs": "10.0.0.0/25\n10.0.1.9", "description": "d"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    async with session_factory() as session:
        z2 = await get_zone(session, zid)
        assert z2 is not None
        assert z2.name == "EditZone2"
        assert z2.cidrs == ["10.0.0.0/25", "10.0.1.9"]


async def test_zone_edit_non_admin_redirect(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    from cybersectool.core.zones import create_zone

    async with session_factory() as session:
        z = await create_zone(session, "EZ", ["10.0.0.0/24"])
        zid = z.id
    await _login(client, session_factory, "ze2", Role.analyst)
    resp = await client.get(f"/zones/{zid}/edit", follow_redirects=False)
    assert resp.status_code == 303  # admin değil → /zones'a yönlendirir


async def test_credential_edit_web(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Admin kimliği düzenler; parola boş bırakılınca korunur."""
    from cybersectool.core.credentials import create_credential, get_credential, get_secret
    from cybersectool.core.models import CredentialType

    async with session_factory() as session:
        c = await create_credential(session, "edc", CredentialType.ssh, "root", "p1")
        cid = c.id
    await _login(client, session_factory, "ce1", Role.admin)
    page = await client.get(f"/credentials/{cid}/edit")
    assert page.status_code == 200
    assert "edc" in page.text
    resp = await client.post(
        f"/credentials/{cid}/edit",
        data={
            "name": "edc2",
            "username": "admin",
            "cred_type": "ssh",
            "password": "",
            "port": "2222",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    async with session_factory() as session:
        c2 = await get_credential(session, cid)
        assert c2 is not None
        assert c2.name == "edc2"
        assert c2.username == "admin"
        assert c2.port == 2222
        assert get_secret(c2) == "p1"  # parola korundu


async def test_credential_edit_non_admin(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "ce2", Role.analyst)
    resp = await client.get("/credentials/1/edit", follow_redirects=False)
    assert resp.status_code == 303  # admin değil → ana sayfaya yönlendirir


async def test_ldap_import_group_web(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Grup içe aktarma: üyeler PASİF kullanıcı olarak oluşur; /users'a yönlendirir."""
    from cybersectool.core.ldap import LdapUser
    from cybersectool.core.ldap_config import save_ldap_config
    from cybersectool.core.users import get_user_by_username
    from cybersectool.web import routes as routes_mod

    async with session_factory() as session:
        await save_ldap_config(
            session,
            server_uri="ldap://x:389",
            use_ssl=False,
            bind_dn="",
            base_dn="dc=x",
            user_filter="(objectClass=person)",
            attr_username="uid",
            attr_email="mail",
            attr_display_name="cn",
            default_role="viewer",
            bind_password=None,
        )

    async def fake_members(
        config: object,
        pw: str,
        group_dn: str,
        *,
        verify_cert: bool = False,
        ca_cert: str | None = None,
    ) -> list[LdapUser]:
        return [
            LdapUser("alice", "a@x", "Alice", "uid=alice,dc=x"),
            LdapUser("bob", None, None, "uid=bob,dc=x"),
        ]

    monkeypatch.setattr(routes_mod, "ldap_group_members", fake_members)
    await _login(client, session_factory, "ldadm", Role.admin)
    resp = await client.post(
        "/ldap/import-group",
        data={"group_dn": "cn=devs,dc=x", "group_name": "devs", "role": "viewer"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "/users" in resp.headers["location"]
    async with session_factory() as session:
        alice = await get_user_by_username(session, "alice")
        assert alice is not None and alice.is_active is False  # pasif geldi


# --- X-2: tarama silme + tekrar tarama ---
async def test_scan_delete_admin(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Admin bir taramayı (ve bulgularını) siler → 303 + tarama kalmaz."""
    from cybersectool.core.models import ScanType
    from cybersectool.core.scans import create_scan, list_scans

    async with session_factory() as session:
        scan = await create_scan(session, ScanType.network, "10.0.0.5")
        sid = scan.id
    await _login(client, session_factory, "del1", Role.admin)
    resp = await client.post(f"/scans/{sid}/delete", follow_redirects=False)
    assert resp.status_code == 303
    async with session_factory() as session:
        assert await list_scans(session) == []


async def test_scan_delete_non_admin_noop(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Analist silemez → 303 (no-op redirect), tarama durur."""
    from cybersectool.core.models import ScanType
    from cybersectool.core.scans import create_scan, list_scans

    async with session_factory() as session:
        scan = await create_scan(session, ScanType.network, "10.0.0.5")
        sid = scan.id
    await _login(client, session_factory, "del2", Role.analyst)
    resp = await client.post(f"/scans/{sid}/delete", follow_redirects=False)
    assert resp.status_code == 303
    async with session_factory() as session:
        assert len(await list_scans(session)) == 1  # silinmedi


async def test_rescan_network_creates_new_scan(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ağ taraması tekrarı → yeni tarama + '(tekrar)' adlı batch oluşur."""
    from cybersectool import dispatch as dispatch_mod
    from cybersectool.core.models import ScanType
    from cybersectool.core.scan_batches import list_batches
    from cybersectool.core.scans import create_scan, list_scans

    monkeypatch.setattr(dispatch_mod.network_scan_task, "delay", lambda *a, **k: None)
    await _scope_and_login(client, session_factory, "rsc1", Role.analyst)
    async with session_factory() as session:
        scan = await create_scan(session, ScanType.network, "10.0.0.5")
        sid = scan.id
    resp = await client.post(f"/scans/{sid}/rescan", follow_redirects=False)
    assert resp.status_code == 303
    async with session_factory() as session:
        scans = await list_scans(session)
        assert len(scans) == 2  # orijinal + tekrar
        batches = await list_batches(session)
        assert any(b.name.endswith("(tekrar)") for b in batches)


async def test_rescan_credentialed_blocked(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Kimlikli denetim tekrar taranamaz (kimlik gerekir) → yeni tarama oluşmaz."""
    from cybersectool.core.models import ScanType
    from cybersectool.core.scans import create_scan, list_scans

    await _scope_and_login(client, session_factory, "rsc2", Role.admin)
    async with session_factory() as session:
        scan = await create_scan(session, ScanType.credentialed, "10.0.0.5")
        sid = scan.id
    resp = await client.post(f"/scans/{sid}/rescan", follow_redirects=False)
    assert resp.status_code == 303
    assert "taranamaz" in resp.headers["location"]
    async with session_factory() as session:
        assert len(await list_scans(session)) == 1  # yeni tarama yok


async def test_credential_zone_edit_web(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Admin kimlik bölgesini düzenler (içindeki kimlikleri değiştirir)."""
    from cybersectool.core.credentials import (
        create_credential,
        create_credential_zone,
        get_credential_zone,
    )
    from cybersectool.core.models import CredentialType

    async with session_factory() as session:
        a = await create_credential(session, "ca", CredentialType.ssh, "u", "p")
        b = await create_credential(session, "cb", CredentialType.ssh, "u", "p")
        z = await create_credential_zone(session, "cz", [a.id])
        zid, bid = z.id, b.id
    await _login(client, session_factory, "cze1", Role.admin)
    resp = await client.post(
        f"/credential-zones/{zid}/edit",
        data={"name": "cz2", "credential_ids": [bid]},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    async with session_factory() as session:
        z2 = await get_credential_zone(session, zid)
        assert z2 is not None
        assert z2.name == "cz2"
        assert z2.credential_ids == [bid]


# --- X-3: denetim panellerine (DB/SNMP/SMB/LDAP/Telnet) IP zone + kimlik bölgesi ---


async def test_audit_snmp_zone_expands_to_up_assets(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SNMP denetimi IP zone seçimiyle envanterdeki AYAKTA varlıklara genişler (per-host)."""
    from cybersectool import dispatch as dispatch_mod
    from cybersectool.core.assets import upsert_asset
    from cybersectool.core.zones import create_zone

    seen: list[str] = []

    async def fake_snmp(session: object, host: str, port: int, **kw: object) -> None:
        seen.append(host)

    monkeypatch.setattr(dispatch_mod, "dispatch_snmp_audit", fake_snmp)
    async with session_factory() as session:
        zone = await create_zone(session, "Z", ["10.0.0.0/24"])
        await upsert_asset(session, "10.0.0.5", is_up=True)
        await upsert_asset(session, "10.0.0.6", is_up=True)
        await upsert_asset(session, "10.0.0.7", is_up=False)  # ayakta değil → atlanır
        await upsert_asset(session, "192.168.1.9", is_up=True)  # zone dışı → atlanır
        zid = zone.id
    await _login(client, session_factory, "ax1", Role.admin)
    resp = await client.post("/scans/snmp", data={"zone_ids": [zid]}, follow_redirects=False)
    assert resp.status_code == 303
    assert sorted(seen) == ["10.0.0.5", "10.0.0.6"]  # yalnız zone içi + ayakta


async def test_audit_smb_single_host_plus_asset(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SMB denetimi: tekil host (geriye dönük) + seçilen tekil IP varlığı birlikte taranır."""
    from cybersectool import dispatch as dispatch_mod
    from cybersectool.core.assets import upsert_asset

    seen: list[str] = []

    async def fake_smb(session: object, host: str, port: int, **kw: object) -> None:
        seen.append(host)

    monkeypatch.setattr(dispatch_mod, "dispatch_smb_audit", fake_smb)
    async with session_factory() as session:
        asset = await upsert_asset(session, "10.0.0.40", is_up=True)
        aid = asset.id
    await _login(client, session_factory, "ax2", Role.admin)
    resp = await client.post(
        "/scans/smb",
        data={"host": "10.0.0.41", "asset_ids": [aid]},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert seen == ["10.0.0.41", "10.0.0.40"]  # tekil host önce, sonra varlık


async def test_audit_snmp_single_host_backward_compat(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Klasik akış korunur: yalnız tekil host gönderince o host taranır."""
    from cybersectool import dispatch as dispatch_mod

    seen: list[str] = []

    async def fake_snmp(session: object, host: str, port: int, **kw: object) -> None:
        seen.append(host)

    monkeypatch.setattr(dispatch_mod, "dispatch_snmp_audit", fake_snmp)
    await _login(client, session_factory, "ax3", Role.admin)
    resp = await client.post(
        "/scans/snmp", data={"host": "10.0.0.30", "port": "161"}, follow_redirects=False
    )
    assert resp.status_code == 303
    assert seen == ["10.0.0.30"]


async def test_audit_snmp_no_target_rejected(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Ne tekil host ne zone/varlık → 400."""
    await _login(client, session_factory, "ax4", Role.admin)
    resp = await client.post("/scans/snmp", data={}, follow_redirects=False)
    assert resp.status_code == 400


async def test_audit_db_credential_zone_picks_type(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DB denetimi: kimlik bölgesinden motora uygun (postgres) kimlik seçilir + zone host'ları."""
    from cybersectool import dispatch as dispatch_mod
    from cybersectool.core.assets import upsert_asset
    from cybersectool.core.credentials import create_credential, create_credential_zone
    from cybersectool.core.models import Credential, CredentialType
    from cybersectool.core.zones import create_zone

    seen: list[tuple[str, str]] = []

    async def fake_db(
        session: object,
        host: str,
        port: int,
        credential: Credential,
        database: str,
        user_id: object,
        **kw: object,
    ) -> None:
        seen.append((host, credential.name))

    monkeypatch.setattr(dispatch_mod, "dispatch_db_audit", fake_db)
    async with session_factory() as session:
        # Bölgede hem ssh (uyumsuz) hem postgres (uyumlu) kimlik var → postgres seçilmeli.
        await create_credential(session, "ssh1", CredentialType.ssh, "u", "p")
        pg = await create_credential(session, "pg1", CredentialType.postgres, "dba", "p")
        cz = await create_credential_zone(session, "dbcz", [pg.id])
        zone = await create_zone(session, "Z", ["10.0.0.0/24"])
        await upsert_asset(session, "10.0.0.20", is_up=True)
        czid, zid = cz.id, zone.id
    await _login(client, session_factory, "ax5", Role.admin)
    resp = await client.post(
        "/scans/db",
        data={"engine": "postgres", "credential_zone_ids": [czid], "zone_ids": [zid]},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert seen == [("10.0.0.20", "pg1")]


async def test_audit_db_no_matching_credential_rejected(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """DB denetimi: motora uygun kimlik yoksa (ne tekil ne bölgede) → 400."""
    from cybersectool.core.credentials import create_credential, create_credential_zone
    from cybersectool.core.models import CredentialType

    async with session_factory() as session:
        ssh = await create_credential(session, "ssh2", CredentialType.ssh, "u", "p")
        cz = await create_credential_zone(session, "cz2", [ssh.id])
        czid = cz.id
    await _login(client, session_factory, "ax6", Role.admin)
    resp = await client.post(
        "/scans/db",
        data={"engine": "postgres", "credential_zone_ids": [czid], "host": "10.0.0.20"},
        follow_redirects=False,
    )
    assert resp.status_code == 400


async def test_audit_telnet_non_admin_forbidden(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Denetim panelleri admin-gated kalır: analist Telnet denetimi yapamaz → 403."""
    await _login(client, session_factory, "ax7", Role.analyst)
    resp = await client.post("/scans/telnet", data={"host": "10.0.0.60"}, follow_redirects=False)
    assert resp.status_code == 403


# --- SCAN-MERGE: /scans/start birleşik backend (yazılan ∪ envanter + zamanlama + kategori) ---


async def test_unified_start_zone_target(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SCAN-MERGE: /scans/start artık envanter hedefi (zone+asset) de kabul eder (sihirbazsız)."""
    from cybersectool import dispatch as dispatch_mod
    from cybersectool.core.assets import upsert_asset
    from cybersectool.core.models import ScopePolicy
    from cybersectool.core.scans import list_scans
    from cybersectool.core.zones import create_zone

    monkeypatch.setattr(dispatch_mod.network_scan_task, "delay", lambda *a, **k: None)
    async with session_factory() as session:
        session.add(
            ScopePolicy(name="s", allowed_cidrs=["10.0.0.0/24"], denied_cidrs=[], is_active=True)
        )
        await session.commit()
        zone = await create_zone(session, "Z", ["10.0.0.0/24"])
        asset = await upsert_asset(session, "10.0.0.5")
        zid, aid = zone.id, asset.id
    await _login(client, session_factory, "um1", Role.analyst)
    resp = await client.post(
        "/scans/start",
        data={"zone_ids": [zid], "asset_ids": [aid], "mode": "network", "name": "Birleşik"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    async with session_factory() as session:
        scans = await list_scans(session)
        assert len(scans) == 1
        assert "10.0.0.0/24" in scans[0].target and "10.0.0.5" in scans[0].target


async def test_unified_start_schedule(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SCAN-MERGE: /scans/start + sched_mode=schedule → hemen başlamaz, ScheduledScan oluşur."""
    from cybersectool import dispatch as dispatch_mod
    from cybersectool.core.assets import upsert_asset
    from cybersectool.core.models import ScopePolicy
    from cybersectool.core.scans import list_scans
    from cybersectool.core.schedules import list_schedules

    monkeypatch.setattr(dispatch_mod.network_scan_task, "delay", lambda *a, **k: None)
    async with session_factory() as session:
        session.add(
            ScopePolicy(name="s", allowed_cidrs=["10.0.0.0/24"], denied_cidrs=[], is_active=True)
        )
        await session.commit()
        asset = await upsert_asset(session, "10.0.0.5")
        aid = asset.id
    await _login(client, session_factory, "um2", Role.analyst)
    resp = await client.post(
        "/scans/start",
        data={
            "asset_ids": [aid],
            "mode": "network",
            "name": "Zaman",
            "sched_mode": "schedule",
            "sched_period": "weekly",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "zamanland" in resp.headers["location"]
    async with session_factory() as session:
        assert len(await list_schedules(session)) == 1
        assert await list_scans(session) == []  # hemen tarama başlamadı


async def test_unified_start_schedule_typed_only_rejected(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """SCAN-MERGE: yazılan-hedef + zamanlama → 400 (zamanlı tarama envanter hedefi ister)."""
    await _login(client, session_factory, "um3", Role.analyst)
    resp = await client.post(
        "/scans/start",
        data={"targets": "10.0.0.5", "mode": "network", "sched_mode": "schedule"},
        follow_redirects=False,
    )
    assert resp.status_code == 400
