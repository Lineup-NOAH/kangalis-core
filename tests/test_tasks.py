"""Celery yapılandırması ve örnek görev mantığı testleri."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.models import ScanStatus, ScanType
from cybersectool.core.scans import create_scan, get_scan
from cybersectool.tasks.celery_app import celery_app
from cybersectool.tasks.example import _run_demo


def test_celery_app_configured() -> None:
    assert celery_app.main == "cybersectool"
    assert "redis://" in str(celery_app.conf.broker_url)


async def test_run_demo_updates_scan(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        scan = await create_scan(session, ScanType.network, "demo")
        result = await _run_demo(session, scan.id)
        assert result == "completed"
        refreshed = await get_scan(session, scan.id)
        assert refreshed is not None
        assert refreshed.status == ScanStatus.completed
