"""Güvenlik raporu sayfası testleri (tarama-bazlı)."""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.findings import create_finding
from cybersectool.core.models import Role, ScanType, Severity
from cybersectool.core.scans import create_scan
from cybersectool.core.users import create_user


async def test_report_list_renders(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """/report artık tarama-bazlı rapor LİSTESİ gösterir."""
    async with session_factory() as session:
        await create_user(session, "vi", "pass1234", role=Role.viewer)
        scan = await create_scan(session, ScanType.network, "10.0.0.5", created_by=None)
        await create_finding(session, scan.id, "Açık port", severity=Severity.high)
    await client.post("/auth/login", json={"username": "vi", "password": "pass1234"})
    resp = await client.get("/report")
    assert resp.status_code == 200
    assert "Raporlar" in resp.text
    assert "10.0.0.5" in resp.text  # tarama listede görünür


async def test_report_per_scan_renders(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """/report/{scan_id} yalnızca o taramanın raporunu gösterir."""
    async with session_factory() as session:
        await create_user(session, "vi2", "pass1234", role=Role.viewer)
        scan = await create_scan(session, ScanType.network, "10.0.0.9", created_by=None)
        await create_finding(session, scan.id, "Zafiyet X", severity=Severity.critical)
        scan_id = scan.id
    await client.post("/auth/login", json={"username": "vi2", "password": "pass1234"})
    resp = await client.get(f"/report/{scan_id}")
    assert resp.status_code == 200
    assert "Güvenlik Raporu" in resp.text
    assert "Özet" in resp.text
    assert "10.0.0.9" in resp.text


async def test_report_per_scan_not_found(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    async with session_factory() as session:
        await create_user(session, "vi3", "pass1234", role=Role.viewer)
    await client.post("/auth/login", json={"username": "vi3", "password": "pass1234"})
    resp = await client.get("/report/99999", follow_redirects=False)
    assert resp.status_code == 303  # liste sayfasına yönlendirir


async def test_report_batch_one_named_row(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Tarama işi (ScanBatch): raporlarda tek isimli satır; batch raporu bulguları toplar."""
    from cybersectool.core.scan_batches import create_batch
    from cybersectool.core.scans import create_scan as _create_scan

    async with session_factory() as session:
        await create_user(session, "bvi", "pass1234", role=Role.viewer)
        batch = await create_batch(session, "Haftalık tarama", created_by=None)
        s1 = await _create_scan(session, ScanType.network, "10.0.0.1", batch_id=batch.id)
        s2 = await _create_scan(session, ScanType.network, "10.0.0.2", batch_id=batch.id)
        await create_finding(session, s1.id, "Bulgu A", severity=Severity.high)
        await create_finding(session, s2.id, "Bulgu B", severity=Severity.critical)
        batch_id = batch.id
    await client.post("/auth/login", json={"username": "bvi", "password": "pass1234"})
    # Liste: isimli tek satır
    lst = await client.get("/report")
    assert lst.status_code == 200
    assert "Haftalık tarama" in lst.text
    assert "10.0.0.1" not in lst.text  # üye taramalar ayrı satır DEĞİL
    # Batch raporu: iki taramanın bulguları toplanır
    rep = await client.get(f"/report/batch/{batch_id}")
    assert rep.status_code == 200
    assert "Haftalık tarama" in rep.text
    assert "Bulgu A" in rep.text and "Bulgu B" in rep.text


async def test_report_lists_discovered_hosts(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Rapor 'Bulunan Hostlar' bölümü: kapsam içi IP'ler + bilgileri (port/servis) yazar."""
    from cybersectool.core.assets import upsert_asset, upsert_service

    async with session_factory() as session:
        await create_user(session, "rh", "pass1234", role=Role.viewer)
        scan = await create_scan(session, ScanType.ping, "10.0.0.0/24", created_by=None)
        scan_id = scan.id
        # Ping ile ayakta (servissiz) → görünmeli, "port taranmadı" notu.
        await upsert_asset(session, "10.0.0.5", is_up=True)
        # Servisli host → port/servis bilgisi yazılmalı.
        served = await upsert_asset(session, "10.0.0.6", is_up=True)
        await upsert_service(session, served.id, 80, service_name="http", product="nginx")
        # Kapsam DIŞI host → raporda görünmemeli.
        await upsert_asset(session, "10.0.99.9", is_up=True)
    await client.post("/auth/login", json={"username": "rh", "password": "pass1234"})
    resp = await client.get(f"/report/{scan_id}")
    assert resp.status_code == 200
    assert "Bulunan Hostlar" in resp.text
    assert "10.0.0.5" in resp.text  # ping ile bulunan IP
    assert "10.0.0.6" in resp.text and "nginx" in resp.text  # servis bilgisi yazıldı
    assert "10.0.99.9" not in resp.text  # kapsam dışı host yok


async def test_web_report_shows_target_not_inventory(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Web taraması raporu: iç envanteri DEĞİL, taranan URL'in host'unu (çözülen IP) gösterir."""
    from cybersectool.core.assets import upsert_asset

    async with session_factory() as session:
        await create_user(session, "wrh", "pass1234", role=Role.viewer)
        # Envanterde iç-ağ host'ları — WEB raporunda GÖRÜNMEMELİ (eski hata: hepsi sızıyordu).
        await upsert_asset(session, "10.0.0.5", is_up=True)
        await upsert_asset(session, "192.168.1.50", is_up=True)
        scan = await create_scan(session, ScanType.web, "https://site.example", created_by=None)
        scan.resolved_ip = "93.184.216.34"
        await session.commit()
        scan_id = scan.id
    await client.post("/auth/login", json={"username": "wrh", "password": "pass1234"})
    resp = await client.get(f"/report/{scan_id}")
    assert resp.status_code == 200
    assert "93.184.216.34" in resp.text  # taranan host'un çözülen IP'si var
    assert "10.0.0.5" not in resp.text  # iç envanter SIZMADI
    assert "192.168.1.50" not in resp.text


async def test_web_report_directory_section(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Dizin taraması bulguları raporda ayrı 'Bulunan Yollar' bölümünde görünür."""
    from cybersectool.core.findings import create_finding

    async with session_factory() as session:
        await create_user(session, "wdr", "pass1234", role=Role.viewer)
        scan = await create_scan(session, ScanType.web, "https://x.example", created_by=None)
        await create_finding(
            session, scan.id, "Bulunan yol: /admin (HTTP 200)", severity=Severity.info
        )
        await create_finding(
            session, scan.id, "Bulunan yol: /.git/config (HTTP 200)", severity=Severity.medium
        )
        await create_finding(
            session, scan.id, "Eksik güvenlik başlığı: CSP", severity=Severity.medium
        )
        scan_id = scan.id
    await client.post("/auth/login", json={"username": "wdr", "password": "pass1234"})
    resp = await client.get(f"/report/{scan_id}")
    assert resp.status_code == 200
    assert "Bulunan Yollar" in resp.text  # ayrı bölüm başlığı
    assert "/admin (HTTP 200)" in resp.text  # keşfedilen yol
    assert "/.git/config (HTTP 200)" in resp.text  # hassas yol
    assert "Eksik güvenlik başlığı: CSP" in resp.text  # genel bulgu da listede kalır


async def test_report_requires_auth(client: AsyncClient) -> None:
    resp = await client.get("/report", follow_redirects=False)
    assert resp.status_code == 303
