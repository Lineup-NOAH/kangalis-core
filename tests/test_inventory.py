"""Envanter/tarama core servis testleri (Asset/Service/Scan/Finding)."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.assets import count_assets, list_assets, upsert_asset, upsert_service
from cybersectool.core.findings import count_open_findings, create_finding, list_findings
from cybersectool.core.models import ScanStatus, ScanType, Severity
from cybersectool.core.scans import count_scans, create_scan, set_scan_status


async def test_asset_upsert_is_idempotent(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as s:
        a1 = await upsert_asset(s, "10.0.0.5", hostname="host1")
        a2 = await upsert_asset(s, "10.0.0.5", os="Linux")
        assert a1.id == a2.id
        assert a2.hostname == "host1"  # korunur
        assert a2.os == "Linux"
        assert await count_assets(s) == 1
        assert len(await list_assets(s)) == 1


async def test_service_upsert_unique_per_port(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as s:
        asset = await upsert_asset(s, "10.0.0.6")
        s1 = await upsert_service(s, asset.id, 22, service_name="ssh")
        s2 = await upsert_service(s, asset.id, 22, version="8.9")
        assert s1.id == s2.id
        assert s2.service_name == "ssh"
        assert s2.version == "8.9"


async def test_scan_lifecycle(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as s:
        scan = await create_scan(s, ScanType.network, "10.0.0.0/24")
        assert scan.status == ScanStatus.pending
        assert await count_scans(s) == 1

        running = await set_scan_status(s, scan.id, ScanStatus.running)
        assert running is not None
        assert running.started_at is not None

        done = await set_scan_status(s, scan.id, ScanStatus.completed)
        assert done is not None
        assert done.finished_at is not None


async def test_finding_create_and_filter(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as s:
        asset = await upsert_asset(s, "10.0.0.7")
        svc = await upsert_service(s, asset.id, 80, service_name="http")
        scan = await create_scan(s, ScanType.network, "10.0.0.7")
        await create_finding(
            s,
            scan.id,
            "Eski Apache",
            severity=Severity.high,
            asset_id=asset.id,
            service_id=svc.id,
            cve_id="CVE-2024-0001",
        )
        assert await count_open_findings(s) == 1
        highs = await list_findings(s, severity=Severity.high)
        assert len(highs) == 1
        assert highs[0].cve_id == "CVE-2024-0001"
        assert len(await list_findings(s, severity=Severity.low)) == 0
