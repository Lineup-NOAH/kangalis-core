"""Canlı tarama takibi: ilerleme + canlı sayfa/panel + durdurma (iptal)."""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.models import Role, ScanStatus, ScanType
from cybersectool.core.scans import create_scan, get_scan, set_scan_progress, set_scan_status
from cybersectool.core.users import create_user


async def test_set_scan_progress(session_factory: async_sessionmaker[AsyncSession]) -> None:
    async with session_factory() as session:
        scan = await create_scan(session, ScanType.network, "10.0.0.5")
        updated = await set_scan_progress(session, scan.id, 55, "nmap çalışıyor")
        assert updated is not None
        assert updated.progress == 55 and updated.phase == "nmap çalışıyor"
        # sınırlar 0-100'e kelepçelenir
        clamped = await set_scan_progress(session, scan.id, 250)
        assert clamped is not None and clamped.progress == 100


async def test_completed_status_forces_full_progress(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """set_scan_status(completed) progress yazmasa bile %100 + 'Tamamlandı' yapar.

    Tek noktadan tüm türleri (sca/kimlikli denetim/hardening) kapsar — eskiden bu türler
    bitince %0/'Başlatılıyor'da takılı kalıyordu.
    """
    async with session_factory() as session:
        scan = await create_scan(session, ScanType.credentialed, "10.0.0.5")
        updated = await set_scan_status(session, scan.id, ScanStatus.completed)
        assert updated is not None
        assert updated.progress == 100
        assert updated.phase == "Tamamlandı"


async def test_running_status_sets_default_phase(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """set_scan_status(running): faz boşsa 'Çalışıyor' (kalıcı 'Başlatılıyor' takılması yok)."""
    async with session_factory() as session:
        scan = await create_scan(session, ScanType.sca, "manifest")
        updated = await set_scan_status(session, scan.id, ScanStatus.running)
        assert updated is not None
        assert updated.phase == "Çalışıyor"


async def _login(
    client: AsyncClient,
    factory: async_sessionmaker[AsyncSession],
    username: str,
    role: Role = Role.analyst,
) -> None:
    async with factory() as session:
        await create_user(session, username, "pass1234", role=role)
    await client.post("/auth/login", json={"username": username, "password": "pass1234"})


async def test_scan_live_page_and_panel(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    async with session_factory() as session:
        scan = await create_scan(session, ScanType.network, "10.0.0.5")
        await set_scan_status(session, scan.id, ScanStatus.running)
        await set_scan_progress(session, scan.id, 40, "Servisler işleniyor")
        scan_id = scan.id
    await _login(client, session_factory, "lv1")
    page = await client.get(f"/scans/{scan_id}/live")
    assert page.status_code == 200
    assert "Canlı Takip" in page.text
    assert "10.0.0.5" in page.text
    panel = await client.get(f"/scans/{scan_id}/live/panel")
    assert panel.status_code == 200
    assert "%40" in panel.text  # ilerleme yüzdesi
    assert "Servisler işleniyor" in panel.text


async def test_completed_web_scan_panel_shows_100(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Tamamlanan web taraması canlı panelde %100 + durum gösterir (eskiden %0/'Başlatılıyor')."""
    async with session_factory() as session:
        scan = await create_scan(session, ScanType.web, "https://x.example")
        # progress'e dokunmadan tamamla — eski hata: web görevi progress yazmıyordu → %0 takılı.
        await set_scan_status(session, scan.id, ScanStatus.completed)
        scan_id = scan.id
    await _login(client, session_factory, "lvw")
    panel = await client.get(f"/scans/{scan_id}/live/panel")
    assert panel.status_code == 200
    assert "%100" in panel.text  # tamamlandıysa ilerleme dolu
    assert "Başlatılıyor" not in panel.text  # 'Başlatılıyor…' fazında takılı kalmaz


async def test_stop_scan_cancels(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    async with session_factory() as session:
        scan = await create_scan(session, ScanType.network, "10.0.0.5")
        await set_scan_status(session, scan.id, ScanStatus.running)
        scan_id = scan.id
    await _login(client, session_factory, "lv2", Role.analyst)
    resp = await client.post(f"/scans/{scan_id}/stop", follow_redirects=False)
    assert resp.status_code == 303
    async with session_factory() as session:
        scan = await get_scan(session, scan_id)
        assert scan is not None and scan.status == ScanStatus.cancelled


async def test_stop_scan_viewer_forbidden(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    async with session_factory() as session:
        scan = await create_scan(session, ScanType.network, "10.0.0.5")
        await set_scan_status(session, scan.id, ScanStatus.running)
        scan_id = scan.id
    await _login(client, session_factory, "lv3", Role.viewer)
    resp = await client.post(f"/scans/{scan_id}/stop", follow_redirects=False)
    assert resp.status_code == 303  # /scans'e yönlendirir, iptal etmez
    async with session_factory() as session:
        scan = await get_scan(session, scan_id)
        assert scan is not None and scan.status == ScanStatus.running  # değişmedi
