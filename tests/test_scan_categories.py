"""Tarama kategori filtresi: categories_for_cves + create_scan + wizard + rapor filtresi."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.exploits import categories_for_cves
from cybersectool.core.findings import create_finding
from cybersectool.core.models import Exploit, ExploitSource, Role, ScanType, Severity
from cybersectool.core.scans import create_scan
from cybersectool.core.users import create_user


def _exploit(cve_text: str, category_text: str, ext: str) -> Exploit:
    return Exploit(
        source=ExploitSource.exploitdb,
        external_id=ext,
        title="t",
        cve_text=cve_text,
        category_text=category_text,
    )


async def test_categories_for_cves(session_factory: async_sessionmaker[AsyncSession]) -> None:
    async with session_factory() as session:
        session.add(_exploit("CVE-2024-1 CVE-2024-2", "windows database", "1"))
        session.add(_exploit("CVE-2024-3", "linux", "2"))
        await session.commit()
        res = await categories_for_cves(session, ["CVE-2024-1", "CVE-2024-3", "CVE-2099-9"])
        assert res["CVE-2024-1"] == {"windows", "database"}
        assert res["CVE-2024-3"] == {"linux"}
        assert res["CVE-2099-9"] == set()


async def test_create_scan_stores_categories(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        scan = await create_scan(
            session, ScanType.network, "10.0.0.5", categories=["windows", "web"]
        )
        assert scan.categories == ["windows", "web"]
        plain = await create_scan(session, ScanType.network, "10.0.0.6")
        assert plain.categories == []


async def _login(
    client: AsyncClient,
    factory: async_sessionmaker[AsyncSession],
    username: str,
    role: Role = Role.admin,
) -> None:
    async with factory() as session:
        await create_user(session, username, "pass1234", role=role)
    await client.post("/auth/login", json={"username": username, "password": "pass1234"})


async def test_report_category_filter(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Tarama kategorisi 'windows' ise rapor yalnızca windows CVE + CVE'siz bulguyu gösterir."""
    async with session_factory() as session:
        session.add(_exploit("CVE-WIN-1", "windows", "w1"))
        session.add(_exploit("CVE-LIN-1", "linux", "l1"))
        await session.commit()
        scan = await create_scan(session, ScanType.network, "10.0.0.5", categories=["windows"])
        await create_finding(session, scan.id, "Windows zafiyeti", cve_id="CVE-WIN-1")
        await create_finding(session, scan.id, "Linux zafiyeti", cve_id="CVE-LIN-1")
        await create_finding(session, scan.id, "Yapilandirma bulgusu", severity=Severity.medium)
        scan_id = scan.id
    await _login(client, session_factory, "rc1")
    resp = await client.get(f"/report/{scan_id}")
    assert resp.status_code == 200
    assert "Windows zafiyeti" in resp.text  # windows CVE → gösterilir
    assert "Yapilandirma bulgusu" in resp.text  # CVE'siz → gösterilir
    assert "Linux zafiyeti" not in resp.text  # linux CVE → filtre dışı


async def test_wizard_stores_categories(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sihirbazdan seçilen kategoriler oluşturulan taramaya kaydedilir."""
    from cybersectool import dispatch as dispatch_mod
    from cybersectool.core.assets import upsert_asset
    from cybersectool.core.models import ScopePolicy
    from cybersectool.core.scans import list_scans

    monkeypatch.setattr(dispatch_mod.network_scan_task, "delay", lambda *a, **k: None)
    async with session_factory() as session:
        session.add(
            ScopePolicy(name="s", allowed_cidrs=["10.0.0.0/24"], denied_cidrs=[], is_active=True)
        )
        await session.commit()
        asset = await upsert_asset(session, "10.0.0.5")
        aid = asset.id
    await _login(client, session_factory, "wc1", Role.analyst)
    resp = await client.post(
        "/scans/wizard",
        data={"asset_ids": [aid], "mode": "safe", "categories": ["windows", "database"]},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    async with session_factory() as session:
        scans = await list_scans(session)
        assert scans and scans[0].categories == ["windows", "database"]
