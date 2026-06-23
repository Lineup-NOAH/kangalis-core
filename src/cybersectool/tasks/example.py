"""Örnek Celery görevi — kuyruk → worker → DB akışını gösterir.

Gerçek tarama görevleri (network_scan, web_scan vb.) bu deseni izler: senkron Celery görevi,
içinde ``asyncio.run`` ile async DB servislerini çağırır. Görev kendi (NullPool)
engine'ini açıp kapatır; böylece worker süreçlerinde event-loop çakışması olmaz.
"""

from __future__ import annotations

import asyncio

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from cybersectool.config import settings
from cybersectool.core.audit import log_action
from cybersectool.core.models import ScanStatus
from cybersectool.core.scans import set_scan_status
from cybersectool.tasks.celery_app import celery_app


async def _run_demo(session: AsyncSession, scan_id: int) -> str:
    """Bir scan'i running → completed yapar ve denetim günlüğü yazar (test edilebilir)."""
    await set_scan_status(session, scan_id, ScanStatus.running)
    await set_scan_status(session, scan_id, ScanStatus.completed)
    await log_action(session, "demo_task", target=f"scan:{scan_id}")
    return "completed"


async def _with_session(scan_id: int) -> str:
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as session:
            return await _run_demo(session, scan_id)
    finally:
        await engine.dispose()


@celery_app.task(name="demo_task")
def demo_task(scan_id: int) -> str:
    return asyncio.run(_with_session(scan_id))
