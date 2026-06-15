"""Sunucu-taraflı PDF rapor testleri.

WeasyPrint yerel kütüphaneleri (Pango/Cairo) her ortamda bulunmaz. Testler iki
durumu da doğru biçimde ele alır: kütüphane varsa gerçek PDF üretilir (%PDF
sihirli baytları), yoksa rota 503 döner.
"""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.models import Role, ScanType
from cybersectool.core.scans import create_scan
from cybersectool.core.users import create_user
from cybersectool.web.pdf import pdf_available, render_html_to_pdf


async def test_report_pdf_requires_auth(client: AsyncClient) -> None:
    resp = await client.get("/report/pdf", follow_redirects=False)
    assert resp.status_code == 303


async def test_report_pdf_route(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    async with session_factory() as session:
        await create_user(session, "vi", "pass1234", role=Role.viewer)
    await client.post("/auth/login", json={"username": "vi", "password": "pass1234"})
    resp = await client.get("/report/pdf")
    if pdf_available():
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/pdf"
        assert resp.content[:4] == b"%PDF"
        assert "attachment" in resp.headers.get("content-disposition", "")
    else:
        assert resp.status_code == 503


async def test_report_per_scan_pdf_route(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Tarama-bazlı PDF: /report/{scan_id}/pdf."""
    async with session_factory() as session:
        await create_user(session, "vp", "pass1234", role=Role.viewer)
        scan = await create_scan(session, ScanType.network, "10.0.0.5", created_by=None)
        scan_id = scan.id
    await client.post("/auth/login", json={"username": "vp", "password": "pass1234"})
    resp = await client.get(f"/report/{scan_id}/pdf")
    if pdf_available():
        assert resp.status_code == 200
        assert resp.content[:4] == b"%PDF"
        assert f"tarama-{scan_id}" in resp.headers.get("content-disposition", "")
    else:
        assert resp.status_code == 503


def test_render_html_to_pdf() -> None:
    if not pdf_available():
        return  # WeasyPrint yok — Docker e2e'de doğrulanır
    pdf = render_html_to_pdf("<html><body><h1>Türkçe çğışöü İ test</h1></body></html>")
    assert pdf[:4] == b"%PDF"
    assert len(pdf) > 500
