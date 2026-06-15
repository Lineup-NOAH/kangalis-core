"""Zafiyet (findings) paneli + sıralama testleri."""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.assets import upsert_asset
from cybersectool.core.findings import create_finding, list_findings_by_risk
from cybersectool.core.models import Role, ScanType, Severity
from cybersectool.core.scans import create_scan
from cybersectool.core.users import create_user


async def test_list_findings_by_risk_order(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        asset = await upsert_asset(session, "10.0.0.1")
        scan = await create_scan(session, ScanType.network, "x")
        await create_finding(
            session, scan.id, "low", severity=Severity.low, asset_id=asset.id, risk_score=3.0
        )
        await create_finding(
            session, scan.id, "crit", severity=Severity.critical, asset_id=asset.id, risk_score=9.5
        )
        findings = await list_findings_by_risk(session)
        assert findings[0].risk_score == 9.5
        assert findings[-1].risk_score == 3.0


async def test_findings_page_renders(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    async with session_factory() as session:
        await create_user(session, "an", "pass1234", role=Role.analyst)
    await client.post("/auth/login", json={"username": "an", "password": "pass1234"})
    resp = await client.get("/findings")
    assert resp.status_code == 200
    assert "Zafiyetler" in resp.text
