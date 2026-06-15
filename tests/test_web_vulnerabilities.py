"""Zafiyetler (vulnerabilities) yaşam döngüsü sayfası testleri."""

from __future__ import annotations

from datetime import UTC, datetime

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.assets import upsert_asset
from cybersectool.core.models import (
    CVE,
    FindingStatus,
    Role,
    ScanType,
    Severity,
    Vulnerability,
)
from cybersectool.core.users import create_user
from cybersectool.core.vulnerabilities import get_vulnerability


async def _login(client: AsyncClient, username: str, password: str) -> None:
    resp = await client.post("/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200


async def _seed(
    session: AsyncSession,
) -> tuple[int, int]:
    """2 varlık + her birine bir açık ve bir çözülmüş zafiyet ekler.

    Döner: (açık vuln id, çözülmüş vuln id).
    """
    a1 = await upsert_asset(session, "10.0.0.1")
    a2 = await upsert_asset(session, "10.0.0.2")
    now = datetime.now(UTC)
    open_vuln = Vulnerability(
        asset_id=a1.id,
        fingerprint="cve:CVE-2024-0001",
        scan_type=ScanType.network,
        title="Acik zafiyet ornek",
        severity=Severity.high,
        cve_id="CVE-2024-0001",
        risk_score=8.0,
        status=FindingStatus.open,
        first_seen=now,
        last_seen=now,
    )
    resolved_vuln = Vulnerability(
        asset_id=a2.id,
        fingerprint="cve:CVE-2024-0002",
        scan_type=ScanType.network,
        title="Cozulmus zafiyet ornek",
        severity=Severity.medium,
        cve_id="CVE-2024-0002",
        risk_score=5.0,
        status=FindingStatus.resolved,
        resolved_at=now,
        first_seen=now,
        last_seen=now,
    )
    session.add(open_vuln)
    session.add(resolved_vuln)
    await session.commit()
    await session.refresh(open_vuln)
    await session.refresh(resolved_vuln)
    return open_vuln.id, resolved_vuln.id


async def test_active_tab_shows_only_open(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    async with session_factory() as session:
        await create_user(session, "admin", "pass1234", role=Role.admin)
        await _seed(session)
    await _login(client, "admin", "pass1234")
    resp = await client.get("/vulnerabilities")
    assert resp.status_code == 200
    assert "Zafiyetli" in resp.text
    assert "Çözülenler" in resp.text
    assert "Acik zafiyet ornek" in resp.text
    assert "Cozulmus zafiyet ornek" not in resp.text


async def test_resolved_tab_shows_resolved(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    async with session_factory() as session:
        await create_user(session, "admin", "pass1234", role=Role.admin)
        await _seed(session)
    await _login(client, "admin", "pass1234")
    resp = await client.get("/vulnerabilities?tab=resolved")
    assert resp.status_code == 200
    assert "Cozulmus zafiyet ornek" in resp.text
    assert "Acik zafiyet ornek" not in resp.text


async def test_per_whitelist(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    async with session_factory() as session:
        await create_user(session, "admin", "pass1234", role=Role.admin)
        await _seed(session)
    await _login(client, "admin", "pass1234")
    ok = await client.get("/vulnerabilities?per=100&page=1")
    assert ok.status_code == 200
    # Geçersiz per → 10'a düşer, yine 200.
    bad = await client.get("/vulnerabilities?per=7")
    assert bad.status_code == 200


async def test_triage_status_change(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    async with session_factory() as session:
        await create_user(session, "admin", "pass1234", role=Role.admin)
        open_id, _ = await _seed(session)
    await _login(client, "admin", "pass1234")
    resp = await client.post(
        f"/vulnerabilities/{open_id}/status",
        data={"status": "accepted_risk", "note": "bilinen risk", "tab": "active"},
    )
    assert resp.status_code == 303
    async with session_factory() as session:
        v = await get_vulnerability(session, open_id)
        assert v is not None
        assert v.status == FindingStatus.accepted_risk
        assert v.note == "bilinen risk"


async def test_urgent_badge_renders(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """VI-1: KEV işaretli CVE'li açık vuln → sayfada ACİL rozeti görünür."""
    async with session_factory() as session:
        await create_user(session, "admin", "pass1234", role=Role.admin)
        await _seed(session)
        # Açık vuln'ün CVE'sini KEV (aktif sömürü) olarak işaretle → acil olur.
        session.add(CVE(cve_id="CVE-2024-0001", cvss_score=7.5, kev_flag=True))
        await session.commit()
    await _login(client, "admin", "pass1234")
    resp = await client.get("/vulnerabilities")
    assert resp.status_code == 200
    assert "ACİL" in resp.text  # urgent rozeti render edildi
    # Çözülmüş vuln'ün CVE'si yok → orada acil yok (resolved sekmesi temiz).
    resolved = await client.get("/vulnerabilities?tab=resolved")
    assert "ACİL" not in resolved.text


async def test_viewer_cannot_triage(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    async with session_factory() as session:
        await create_user(session, "viewer", "pass1234", role=Role.viewer)
        open_id, _ = await _seed(session)
    await _login(client, "viewer", "pass1234")
    resp = await client.post(
        f"/vulnerabilities/{open_id}/status",
        data={"status": "accepted_risk", "tab": "active"},
    )
    # Viewer → "/" yönlendirme, değişiklik uygulanmaz.
    assert resp.status_code == 303
    async with session_factory() as session:
        v = await get_vulnerability(session, open_id)
        assert v is not None
        assert v.status == FindingStatus.open
