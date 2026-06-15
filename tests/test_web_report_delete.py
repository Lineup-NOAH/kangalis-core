"""Rapor silme (batch/scan) web akışı testleri."""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.findings import create_finding
from cybersectool.core.models import Finding, Role, Scan, ScanBatch, ScanType, Severity
from cybersectool.core.scan_batches import create_batch
from cybersectool.core.scans import create_scan
from cybersectool.core.users import create_user


async def _login(
    client: AsyncClient,
    factory: async_sessionmaker[AsyncSession],
    username: str,
    role: Role,
) -> None:
    async with factory() as session:
        await create_user(session, username, "pass1234", role=role)
    await client.post("/auth/login", json={"username": username, "password": "pass1234"})


async def _seed_batch(
    factory: async_sessionmaker[AsyncSession],
) -> tuple[int, int, int]:
    """İsimli bir ScanBatch + üye Scan + Finding oluşturur. (batch_id, scan_id, finding_id)."""
    async with factory() as session:
        batch = await create_batch(session, "Silinecek iş")
        scan = await create_scan(session, ScanType.network, "10.0.0.5", batch_id=batch.id)
        finding = await create_finding(session, scan.id, "Açık port", Severity.high)
        return batch.id, scan.id, finding.id


async def _seed_standalone(
    factory: async_sessionmaker[AsyncSession],
) -> tuple[int, int]:
    """Batch'e bağlı olmayan tekil bir Scan + Finding oluşturur. (scan_id, finding_id)."""
    async with factory() as session:
        scan = await create_scan(session, ScanType.network, "10.0.0.9")
        finding = await create_finding(session, scan.id, "Zafiyet", Severity.critical)
        return scan.id, finding.id


async def test_admin_delete_batch_cascades(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Admin batch raporunu siler → batch + üye taramalar + bulgular gider."""
    batch_id, scan_id, finding_id = await _seed_batch(session_factory)
    await _login(client, session_factory, "radm1", Role.admin)
    resp = await client.post(f"/report/batch/{batch_id}/delete", follow_redirects=False)
    assert resp.status_code == 303
    assert "/report" in resp.headers["location"]
    async with session_factory() as session:
        assert await session.get(ScanBatch, batch_id) is None
        assert await session.get(Scan, scan_id) is None
        assert await session.get(Finding, finding_id) is None


async def test_admin_delete_standalone_scan_cascades(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Admin tekil tarama raporunu siler → tarama + bulguları gider."""
    scan_id, finding_id = await _seed_standalone(session_factory)
    await _login(client, session_factory, "radm2", Role.admin)
    resp = await client.post(f"/report/{scan_id}/delete", follow_redirects=False)
    assert resp.status_code == 303
    assert "/report" in resp.headers["location"]
    async with session_factory() as session:
        assert await session.get(Scan, scan_id) is None
        assert await session.get(Finding, finding_id) is None


async def test_viewer_delete_batch_forbidden(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Viewer batch silemez → '/' yönlendirir, veri durur."""
    batch_id, scan_id, finding_id = await _seed_batch(session_factory)
    await _login(client, session_factory, "rview1", Role.viewer)
    resp = await client.post(f"/report/batch/{batch_id}/delete", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/"
    async with session_factory() as session:
        assert await session.get(ScanBatch, batch_id) is not None
        assert await session.get(Scan, scan_id) is not None
        assert await session.get(Finding, finding_id) is not None


async def test_viewer_delete_scan_forbidden(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Viewer tekil tarama silemez → '/' yönlendirir, veri durur."""
    scan_id, finding_id = await _seed_standalone(session_factory)
    await _login(client, session_factory, "rview2", Role.viewer)
    resp = await client.post(f"/report/{scan_id}/delete", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/"
    async with session_factory() as session:
        assert await session.get(Scan, scan_id) is not None
        assert await session.get(Finding, finding_id) is not None


async def test_report_list_delete_button_admin_only(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """/report listesinde silme butonu yalnızca admin'e görünür (can_delete)."""
    batch_id, _scan_id, _finding_id = await _seed_batch(session_factory)
    # Admin: buton var
    await _login(client, session_factory, "radm3", Role.admin)
    admin_page = await client.get("/report")
    assert admin_page.status_code == 200
    assert f"/report/batch/{batch_id}/delete" in admin_page.text
    # Viewer: buton yok
    await _login(client, session_factory, "rview3", Role.viewer)
    viewer_page = await client.get("/report")
    assert viewer_page.status_code == 200
    assert f"/report/batch/{batch_id}/delete" not in viewer_page.text
