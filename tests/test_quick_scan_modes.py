"""Hızlı tarama tek "Mod" seçici (FAZ VIII-4): sihirbazla AYNI 5 mod + web.

Hızlı tarama artık sihirbazla aynı backend'i (resolve_wizard_mode) kullanır; tek fark
arayüz (çabuk-giriş). Yeni `mode` alanı + eski `scan_type` çağrılarının geriye-uyumlu
eşlemesi doğrulanır.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.models import Role, Scan, ScanMode, ScanType, ScopePolicy
from cybersectool.core.users import create_user
from cybersectool.web.routes import (
    _effective_quick_mode,
    _eta_seconds,
    _resolve_url_hosts,
    _url_host,
)


def test_eta_seconds_nmap_phase_is_stable() -> None:
    """nmap fazında (vuln, %<55) ETA hedef-boyutu tahmininden → büyük+stabil, lineer-yo-yo DEĞİL."""
    from datetime import UTC, datetime, timedelta

    # /24 güvenli vuln, %10, 5sn geçti → tahmin 527; ETA ~522 (lineer olsa 5*(90/10)=45 olurdu).
    scan = Scan(
        scan_type=ScanType.vuln,
        target="172.28.0.0/24",
        mode=ScanMode.safe,
        progress=10,
        started_at=datetime.now(UTC) - timedelta(seconds=5),
    )
    eta = _eta_seconds(scan)
    assert eta is not None and 480 < eta < 530  # boyut-bazlı (lineer 45'ten çok büyük)
    # İşleme kuyruğu (%90 ≥ 55) → klasik lineer (kısa tail): 90sn geçti → 90*(10/90)=10.
    tail = Scan(
        scan_type=ScanType.vuln,
        target="172.28.0.0/24",
        mode=ScanMode.safe,
        progress=90,
        started_at=datetime.now(UTC) - timedelta(seconds=90),
    )
    assert _eta_seconds(tail) == 10


def test_url_host() -> None:
    assert _url_host("http://1.2.3.4:80/x") == "1.2.3.4"
    assert _url_host("https://web.kangalis.local/app") == "web.kangalis.local"
    assert _url_host("notaurl") is None


async def test_resolve_url_hosts_ip_passthrough() -> None:
    """IP-host URL → DNS olmadan doğrudan IP; sıra korunur, tekilleştirilir (URL-zone/normal)."""
    assert await _resolve_url_hosts(["http://10.0.0.5:8080/a", "https://10.0.0.5"]) == ["10.0.0.5"]
    assert await _resolve_url_hosts([]) == []


def test_effective_quick_mode_new_and_legacy() -> None:
    """Yeni tek-alan modları doğrudan; eski scan_type+yoğunluk geriye-uyumlu eşlenir."""
    # Yeni (tek alan) — aynen geçer (kimlik artık AYRI MOD DEĞİL).
    for key in ("network", "ping", "cve_safe", "cve_aggressive", "web"):
        assert _effective_quick_mode(key, "network") == key
    # Eski: scan_type + intensity(mode=safe/aggressive).
    assert _effective_quick_mode("safe", "ping") == "ping"
    assert _effective_quick_mode("safe", "web") == "web"
    # SR-3b: sade "web" pasif; eski "agresif web" artık "Web CVE" (web_aggressive) moduna eşlenir.
    assert _effective_quick_mode("aggressive", "web") == "web_aggressive"
    assert _effective_quick_mode("safe", "vuln") == "cve_safe"
    assert _effective_quick_mode("aggressive", "vuln") == "cve_aggressive"
    assert _effective_quick_mode("safe", "network") == "network"
    assert _effective_quick_mode("aggressive", "network") == "cve_aggressive"
    # 'credentialed' artık mod değil → ağ taramasına düşer (kimlik add-on olarak çalışır).
    assert _effective_quick_mode("credentialed", "network") == "network"


async def _login(
    client: AsyncClient, fac: async_sessionmaker[AsyncSession], username: str, role: Role
) -> None:
    async with fac() as session:
        await create_user(session, username, "pass1234", role=role)
    await client.post(
        "/login", data={"username": username, "password": "pass1234"}, follow_redirects=False
    )


async def _scope(fac: async_sessionmaker[AsyncSession]) -> None:
    async with fac() as session:
        session.add(
            ScopePolicy(name="s", allowed_cidrs=["10.0.0.0/24"], denied_cidrs=[], is_active=True)
        )
        await session.commit()


async def test_quick_cve_safe(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hızlı tarama mode=cve_safe → ScanType.vuln güvenli; analyst başlatabilir."""
    from cybersectool import dispatch as dispatch_mod
    from cybersectool.core.scans import list_scans

    monkeypatch.setattr(dispatch_mod.network_scan_task, "delay", lambda *a, **k: None)
    await _scope(session_factory)
    await _login(client, session_factory, "qcs", Role.analyst)
    resp = await client.post(
        "/scans/start",
        data={"targets": "10.0.0.5", "mode": "cve_safe"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    async with session_factory() as session:
        scans = await list_scans(session)
        assert scans and scans[0].scan_type == ScanType.vuln
        assert scans[0].mode == ScanMode.safe


async def test_quick_network_ports(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hızlı tarama mode=network + elle port → kayda yazılır."""
    from cybersectool import dispatch as dispatch_mod
    from cybersectool.core.scans import list_scans

    monkeypatch.setattr(dispatch_mod.network_scan_task, "delay", lambda *a, **k: None)
    await _scope(session_factory)
    await _login(client, session_factory, "qnp", Role.analyst)
    resp = await client.post(
        "/scans/start",
        data={"targets": "10.0.0.5", "mode": "network", "ports": "custom", "ports_custom": "22,80"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    async with session_factory() as session:
        scans = await list_scans(session)
        assert scans and scans[0].scan_type == ScanType.network
        assert scans[0].ports == "22,80"


async def test_quick_cve_aggressive_admin_only(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Hızlı tarama mode=cve_aggressive analyst için 403."""
    await _scope(session_factory)
    await _login(client, session_factory, "qca", Role.analyst)
    resp = await client.post(
        "/scans/start",
        data={"targets": "10.0.0.5", "mode": "cve_aggressive", "aggressive_ack": "on"},
        follow_redirects=False,
    )
    assert resp.status_code == 403


async def test_quick_cve_aggressive_requires_ack(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hızlı tarama mode=cve_aggressive: admin ack'siz 400; ack'le 303 vuln agresif."""
    from cybersectool import dispatch as dispatch_mod
    from cybersectool.core.scans import list_scans

    monkeypatch.setattr(dispatch_mod.network_scan_task, "delay", lambda *a, **k: None)
    await _scope(session_factory)
    await _login(client, session_factory, "qcaadm", Role.admin)
    no_ack = await client.post(
        "/scans/start",
        data={"targets": "10.0.0.5", "mode": "cve_aggressive"},
        follow_redirects=False,
    )
    assert no_ack.status_code == 400
    ok = await client.post(
        "/scans/start",
        data={"targets": "10.0.0.5", "mode": "cve_aggressive", "aggressive_ack": "on"},
        follow_redirects=False,
    )
    assert ok.status_code == 303
    async with session_factory() as session:
        scans = await list_scans(session)
        assert scans and scans[0].scan_type == ScanType.vuln
        assert scans[0].mode == ScanMode.aggressive


async def test_quick_web_mode_ladder(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SR-3b: web_aggressive→ScanMode.aggressive (admin + ack). OSS: web_exploit modu yok."""
    from cybersectool.core.scans import list_scans
    from cybersectool.tasks.web_scan import web_scan_task

    monkeypatch.setattr(web_scan_task, "delay", lambda *a, **k: None)
    await _scope(session_factory)
    await _login(client, session_factory, "qwebadm", Role.admin)
    # web_aggressive: ack ile → 303, ScanType.web + ScanMode.aggressive (Web CVE).
    ok_aggr = await client.post(
        "/scans/start",
        data={"targets": "10.0.0.5", "mode": "web_aggressive", "aggressive_ack": "on"},
        follow_redirects=False,
    )
    assert ok_aggr.status_code == 303
    async with session_factory() as session:
        scans = await list_scans(session)
        assert scans and scans[0].scan_type == ScanType.web
        assert scans[0].mode == ScanMode.aggressive


async def test_quick_url_plus_ip_both_scanned(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SR-3c: CVE modunda IP + URL birlikte → ağ taraması (IP) + web denetimi (URL), aynı batch."""
    from cybersectool import dispatch as dispatch_mod
    from cybersectool.core.scans import list_scans
    from cybersectool.tasks.web_scan import web_scan_task

    monkeypatch.setattr(dispatch_mod.network_scan_task, "delay", lambda *a, **k: None)
    monkeypatch.setattr(web_scan_task, "delay", lambda *a, **k: None)
    await _scope(session_factory)
    await _login(client, session_factory, "qmix", Role.analyst)
    resp = await client.post(
        "/scans/start",
        data={"targets": "10.0.0.5\nhttp://10.0.0.6/app", "mode": "cve_safe"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    async with session_factory() as session:
        scans = await list_scans(session)
        types = {s.scan_type for s in scans}
        assert ScanType.vuln in types  # IP → ağ/CVE taraması
        assert ScanType.web in types  # URL → web denetimi (SR-3c)
        web = [s for s in scans if s.scan_type == ScanType.web]
        assert web and web[0].target == "http://10.0.0.6/app"
        # İkisi de TEK batch'te (kullanıcı tek tarama akışı görür).
        assert len({s.batch_id for s in scans}) == 1


async def test_quick_creds_addon_same_scan(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NESSUS modeli (hızlı): mod + kimlik → AYNI taramaya içeriden bulgular (ayrı satır YOK)."""
    from sqlalchemy import select

    from cybersectool import dispatch as dispatch_mod
    from cybersectool.core.credentials import create_credential
    from cybersectool.core.models import CredentialType, Finding
    from cybersectool.core.scans import list_scans
    from cybersectool.scanners.credentialed import HostFacts
    from cybersectool.scanners.hardening import HardeningFinding

    monkeypatch.setattr(dispatch_mod.network_scan_task, "delay", lambda *a, **k: None)

    async def _ssh_open(host: str, port: int, timeout: float = 2.0) -> bool:
        return port == 22

    async def _fake_cred(
        host: str, port: int, username: str, password: str, *, attempt_privesc: bool = False
    ) -> tuple[HostFacts, list[HardeningFinding]]:
        return HostFacts(os="Ubuntu", kernel="6.0", package_count=5), []

    monkeypatch.setattr(dispatch_mod, "_port_open", _ssh_open)
    monkeypatch.setattr(dispatch_mod, "run_credentialed_scan", _fake_cred)
    await _scope(session_factory)
    async with session_factory() as session:
        cred = await create_credential(session, "ssh1", CredentialType.ssh, "u", "p")
        cid = cred.id
    await _login(client, session_factory, "qadd", Role.admin)
    resp = await client.post(
        "/scans/start",
        data={"targets": "10.0.0.5", "mode": "network", "credential_ids": [cid]},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    async with session_factory() as session:
        scans = await list_scans(session)
        assert len(scans) == 1  # TEK tarama (ayrı credentialed satırı yok)
        assert scans[0].scan_type == ScanType.network
        titles = [
            f.title
            for f in (await session.execute(select(Finding).where(Finding.scan_id == scans[0].id)))
            .scalars()
            .all()
        ]
        assert any(t.startswith("Host envanteri") for t in titles)  # kimlik add-on aynı taramaya


async def test_quick_ping_new_field(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hızlı tarama yeni mode=ping → ping_scan_task'a kuyruğa alınır."""
    from cybersectool import dispatch as dispatch_mod

    enqueued: list[tuple[object, ...]] = []
    monkeypatch.setattr(dispatch_mod.ping_scan_task, "delay", lambda *a, **k: enqueued.append(a))
    await _scope(session_factory)
    await _login(client, session_factory, "qpn", Role.analyst)
    resp = await client.post(
        "/scans/start",
        data={"targets": "10.0.0.5", "mode": "ping"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert len(enqueued) == 1
