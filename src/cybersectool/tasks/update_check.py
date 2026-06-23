"""Günlük "yeni sürüm var mı" denetimi — Celery görevi (beat ile günde bir).

``core/update_check.run_update_check`` çağırır (``force=False`` → ``update_check_enabled``
kapalıysa egress yapmaz). Sonuç DB'ye yazılır; Güncelleme sayfası bunu gösterir. HATA-YUTAR:
ağ/DB hatası worker'ı etkilemez (en kötü ihtimalle o günkü denetim atlanır).
"""

from __future__ import annotations

import asyncio

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from cybersectool.config import settings
from cybersectool.core.audit import log_action
from cybersectool.core.update_check import run_update_check
from cybersectool.tasks.celery_app import celery_app


async def _run() -> str:
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as session:
            result = await run_update_check(session, force=False)
            # Yalnız anlamlı sonuçları denetime yaz (her gün spam etmemek için kısa hedef).
            await log_action(
                session,
                "update_check",
                target=f"{result.current} -> {result.latest or '?'} ({result.status})",
            )
        return f"status={result.status} latest={result.latest or '-'} available={result.available}"
    finally:
        await engine.dispose()


@celery_app.task(name="update_check")
def update_check_task() -> str:
    return asyncio.run(_run())
