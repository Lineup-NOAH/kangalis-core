"""Sihirbaz mod seçici (FAZ VIII-0): 5 mod → backend eşleme + kapılar.

Tek "mod seç" alanı (Ağ / Ping / Güvenli CVE / Agresif CVE / Kimlikli) doğru
``scan_type`` + nmap modu + admin/onay/kimlik kapılarına çözülür. Hızlı tarama ile
AYNI backend'i (resolve_wizard_mode + dispatch_*) paylaşır.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.models import Role, ScanMode, ScanType, ScopePolicy, Severity
from cybersectool.core.scan_policy import resolve_wizard_mode
from cybersectool.core.users import create_user


def test_resolve_wizard_mode_mapping() -> None:
    """Her mod anahtarı doğru scan_type + nmap modu + kapılara eşlenir."""
    net = resolve_wizard_mode("network")
    assert net.scan_type == ScanType.network and net.nmap_mode == ScanMode.safe
    assert net.needs_ports and not net.admin_only and not net.needs_ack

    ping = resolve_wizard_mode("ping")
    assert ping.scan_type == ScanType.ping and not ping.needs_ports

    safe = resolve_wizard_mode("cve_safe")
    assert safe.scan_type == ScanType.vuln and safe.nmap_mode == ScanMode.safe
    assert not safe.needs_ack and not safe.admin_only and not safe.exploit

    # SR-1: agresif CVE artık SÖMÜRMEZ (exploit=False) — yalnız tespit + exploit-göster.
    aggr = resolve_wizard_mode("cve_aggressive")
    assert aggr.scan_type == ScanType.vuln and aggr.nmap_mode == ScanMode.aggressive
    assert aggr.needs_ack and aggr.admin_only and not aggr.exploit

    # OSS açık-kaynak çekirdek: Sömürme (cve_exploit) modu sunulmaz → bilinmeyen anahtar gibi
    # güvenli (sömürmeyen) ağ moduna düşer.
    assert resolve_wizard_mode("cve_exploit").scan_type == ScanType.network


def test_resolve_wizard_mode_legacy_and_unknown() -> None:
    """Eski değerler + bilinmeyen/boş → makul varsayılan. Kimlik artık AYRI MOD DEĞİL."""
    assert resolve_wizard_mode("safe").scan_type == ScanType.network  # eski "güvenli ağ"
    assert resolve_wizard_mode("aggressive").scan_type == ScanType.vuln  # eski "agresif"
    assert resolve_wizard_mode("aggressive").nmap_mode == ScanMode.aggressive
    # 'credentialed' eski bir mod adıydı; Nessus modelinde ağ taramasına düşer (kimlik add-on).
    assert resolve_wizard_mode("credentialed").scan_type == ScanType.network
    assert resolve_wizard_mode("").scan_type == ScanType.network
    assert resolve_wizard_mode("bogus").scan_type == ScanType.network
    assert resolve_wizard_mode(None).scan_type == ScanType.network


async def _login(
    client: AsyncClient, fac: async_sessionmaker[AsyncSession], username: str, role: Role
) -> None:
    async with fac() as session:
        await create_user(session, username, "pass1234", role=role)
    await client.post(
        "/login", data={"username": username, "password": "pass1234"}, follow_redirects=False
    )


async def _scope_asset(fac: async_sessionmaker[AsyncSession], ip: str = "10.0.0.5") -> int:
    from cybersectool.core.assets import upsert_asset

    async with fac() as session:
        session.add(
            ScopePolicy(name="s", allowed_cidrs=["10.0.0.0/24"], denied_cidrs=[], is_active=True)
        )
        await session.commit()
        asset = await upsert_asset(session, ip)
        return asset.id


async def test_wizard_cve_safe_runs_vuln(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Güvenli CVE modu → ScanType.vuln (güvenli); analyst başlatabilir."""
    from cybersectool import dispatch as dispatch_mod
    from cybersectool.core.scans import list_scans

    monkeypatch.setattr(dispatch_mod.network_scan_task, "delay", lambda *a, **k: None)
    aid = await _scope_asset(session_factory)
    await _login(client, session_factory, "wcs", Role.analyst)
    resp = await client.post(
        "/scans/wizard",
        data={"asset_ids": [aid], "mode": "cve_safe"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    async with session_factory() as session:
        scans = await list_scans(session)
        assert scans and scans[0].scan_type == ScanType.vuln
        assert scans[0].mode == ScanMode.safe


async def test_wizard_network_ports_recorded(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ağ modunda elle port seçimi tarama kaydına yazılır (port seçici sihirbazda)."""
    from cybersectool import dispatch as dispatch_mod
    from cybersectool.core.scans import list_scans

    monkeypatch.setattr(dispatch_mod.network_scan_task, "delay", lambda *a, **k: None)
    aid = await _scope_asset(session_factory)
    await _login(client, session_factory, "wnp", Role.analyst)
    resp = await client.post(
        "/scans/wizard",
        data={"asset_ids": [aid], "mode": "network", "ports": "custom", "ports_custom": "80,443"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    async with session_factory() as session:
        scans = await list_scans(session)
        assert scans and scans[0].scan_type == ScanType.network
        assert scans[0].ports == "80,443"


async def test_wizard_cve_aggressive_admin_only(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Agresif CVE modu analyst için yasak (403) — geçerli hedef olsa bile."""
    aid = await _scope_asset(session_factory)
    await _login(client, session_factory, "wca", Role.analyst)
    resp = await client.post(
        "/scans/wizard",
        data={"asset_ids": [aid], "mode": "cve_aggressive", "aggressive_ack": "on"},
        follow_redirects=False,
    )
    assert resp.status_code == 403


async def test_wizard_cve_aggressive_requires_ack(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Agresif CVE: admin + onay tiki yoksa 400; tikle 303 → ScanType.vuln agresif."""
    from cybersectool import dispatch as dispatch_mod
    from cybersectool.core.scans import list_scans

    monkeypatch.setattr(dispatch_mod.network_scan_task, "delay", lambda *a, **k: None)
    aid = await _scope_asset(session_factory)
    await _login(client, session_factory, "wcaadm", Role.admin)
    no_ack = await client.post(
        "/scans/wizard",
        data={"asset_ids": [aid], "mode": "cve_aggressive"},
        follow_redirects=False,
    )
    assert no_ack.status_code == 400
    ok = await client.post(
        "/scans/wizard",
        data={"asset_ids": [aid], "mode": "cve_aggressive", "aggressive_ack": "on"},
        follow_redirects=False,
    )
    assert ok.status_code == 303
    async with session_factory() as session:
        scans = await list_scans(session)
        assert scans and scans[0].scan_type == ScanType.vuln
        assert scans[0].mode == ScanMode.aggressive


async def test_wizard_creds_addon_same_scan(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NESSUS modeli: mod + kimlik → AYNI taramaya içeriden kimlikli bulgular (ayrı satır YOK)."""
    from sqlalchemy import select

    from cybersectool import dispatch as dispatch_mod
    from cybersectool.core.credentials import create_credential
    from cybersectool.core.models import CredentialType, Finding
    from cybersectool.core.scans import list_scans
    from cybersectool.scanners.credentialed import HostFacts
    from cybersectool.scanners.hardening import HardeningFinding

    monkeypatch.setattr(dispatch_mod.network_scan_task, "delay", lambda *a, **k: None)

    async def _ssh_open(host: str, port: int, timeout: float = 2.0) -> bool:
        return port == 22  # SSH açık → kimlikli denetim çalışır

    async def _fake_cred(
        host: str, port: int, username: str, password: str, *, attempt_privesc: bool = False
    ) -> tuple[HostFacts, list[HardeningFinding]]:
        return HostFacts(os="Ubuntu", kernel="6.0", package_count=5), [
            HardeningFinding("CIS bulgusu", Severity.high, "x")
        ]

    monkeypatch.setattr(dispatch_mod, "_port_open", _ssh_open)
    monkeypatch.setattr(dispatch_mod, "run_credentialed_scan", _fake_cred)
    aid = await _scope_asset(session_factory)
    async with session_factory() as session:
        cred = await create_credential(session, "ssh1", CredentialType.ssh, "u", "p")
        cid = cred.id
    await _login(client, session_factory, "wadd", Role.admin)
    resp = await client.post(
        "/scans/wizard",
        data={"asset_ids": [aid], "mode": "cve_safe", "credential_ids": [cid]},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    async with session_factory() as session:
        scans = await list_scans(session)
        assert len(scans) == 1  # TEK tarama (ayrı credentialed satırı yok)
        assert scans[0].scan_type == ScanType.vuln  # dışarıdan teknik
        titles = [
            f.title
            for f in (await session.execute(select(Finding).where(Finding.scan_id == scans[0].id)))
            .scalars()
            .all()
        ]
        # Kimlik add-on AYNI taramaya yazdı (içeriden envanter + CIS bulgusu).
        assert any(t.startswith("Host envanteri") for t in titles)


async def test_wizard_ping_schedule_uses_ping_type(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Ping modu zamanlanınca şablon ScanType.ping taşır (ağ değil)."""
    from cybersectool.core.schedules import list_schedules

    aid = await _scope_asset(session_factory)
    await _login(client, session_factory, "wps", Role.analyst)
    resp = await client.post(
        "/scans/wizard",
        data={
            "asset_ids": [aid],
            "mode": "ping",
            "name": "Günlük keşif",
            "sched_mode": "schedule",
            "sched_period": "daily",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    async with session_factory() as session:
        scheds = await list_schedules(session)
        assert scheds and scheds[0].scan_type == ScanType.ping
        assert scheds[0].name == "Günlük keşif"
