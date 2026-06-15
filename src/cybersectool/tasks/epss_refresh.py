"""Tüm CVE'lerin EPSS skorunu günlük tazeleyen + risk skorlarını yeniden uygulayan görev.

EPSS (sömürülme olasılığı) günlük değişir; tazeleyip ``apply_risk_scores`` ile
Finding + Vulnerability risk skorlarını yeniden hesaplar → zafiyet sayfasındaki
önceliklendirme (ve "acil" kovası) güncel kalır (VI-1).
"""

from __future__ import annotations

import asyncio

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from cybersectool.config import settings
from cybersectool.core.audit import log_action
from cybersectool.core.models import CVE
from cybersectool.core.vuln import apply_risk_scores
from cybersectool.intel.epss import fetch_epss
from cybersectool.tasks.celery_app import celery_app


async def _run() -> str:
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as session:
            cve_ids = [row[0] for row in (await session.execute(select(CVE.cve_id))).all()]
        if not cve_ids:
            return "no cves"
        epss = await fetch_epss(cve_ids)
        async with factory() as session:
            updated = 0
            for cve_id, score in epss.items():
                cve = await session.get(CVE, cve_id)
                if cve is not None:
                    cve.epss_score = score
                    updated += 1
            await session.commit()
            # Risk skorlarını yeniden uygula (EPSS + exploit sinyali güncel).
            await apply_risk_scores(session, cve_ids)
            await log_action(
                session, "epss_refresh", target=f"cves={len(cve_ids)} updated={updated}"
            )
        return f"cves={len(cve_ids)} updated={updated}"
    finally:
        await engine.dispose()


@celery_app.task(name="epss_refresh")
def refresh_epss_task() -> str:
    return asyncio.run(_run())
