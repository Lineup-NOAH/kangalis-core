"""NVD CVE + CPE konfigürasyonlarını yerel depoya çeken Celery görevi.

Offline (ağsız) zafiyet eşleştirme için: bu görev CVE'leri ve CPE eşleşme
ölçütlerini ``cves`` / ``cpe_matches`` tablolarına yazar. Tarama anında artık
NVD'ye gidilmeden bu yerel indeksten eşleştirme yapılabilir.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from cybersectool.config import settings
from cybersectool.core.app_settings import get_nvd_api_key, get_settings, record_cve_sync
from cybersectool.core.audit import log_action
from cybersectool.core.cpe import count_cpe_matches, delete_cves
from cybersectool.core.vuln import upsert_cve
from cybersectool.intel.nvd import CveData, fetch_nvd_cve_data, fetch_nvd_modified
from cybersectool.tasks.celery_app import celery_app

# Her senkronda yakın zamanda GÜNCELLENEN (rescored/CPE değişen/red edilen) CVE'leri tazelemek
# için kullanılan kısa lastMod penceresi (#144 — yalnız yayım penceresi onları kaçırırdı).
NVD_LASTMOD_REFRESH_DAYS = 7


async def _run(
    days: int | None = None, max_pages: int | None = None, *, refresh_modified: bool = True
) -> str:
    # days None → DB ayarındaki nvd_sync_days (CPE indeksi exploit senkronuyla AYNI
    # pencereyi kapsasın); api_key DB'den çözülür (yoksa config fallback).
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as session:
            row = await get_settings(session)
            eff_days = row.nvd_sync_days if days is None else days
            nvd_key = get_nvd_api_key(row) or None
        cves = await fetch_nvd_cve_data(days=eff_days, max_pages=max_pages, api_key=nvd_key)
        rejected_ids: list[str] = []
        if refresh_modified:
            # Son-değişiklik tazeleme pası: yakın zamanda güncellenen eski CVE'ler tazelensin +
            # geç-REDDEDİLEN CVE id'leri toplansın (tek çekiş; ikincisi aşağıda yerelden silinir).
            recent, rejected_ids = await fetch_nvd_modified(
                days=NVD_LASTMOD_REFRESH_DAYS, api_key=nvd_key
            )
            merged: dict[str, CveData] = {c.cve_id: c for c in cves}
            for c in recent:  # aynı cve_id'de lastMod taze → o kazanır
                merged[c.cve_id] = c
            cves = list(merged.values())
        async with factory() as session:
            stored = 0
            match_rows = 0
            for data in cves:
                await upsert_cve(session, data)  # CVE + CPE ölçütlerini yazar
                stored += 1
                match_rows += len([m for m in data.cpe_matches if m.vulnerable])
            # Geç-reddedilen CVE'leri yerelden SİL (kalırsa offline eşleşip sahte bulgu üretir).
            removed = await delete_cves(session, rejected_ids)
            total = await count_cpe_matches(session)
            # CVE/CPE bilgi bankası tazeliği (Zafiyet DB sayfası + Ayarlar paneli gösterir).
            await record_cve_sync(session, datetime.now(UTC))
            await log_action(
                session,
                "cpe_sync",
                target=f"cve={stored} yeni~={match_rows} silinen={removed} toplam_cpe={total}",
            )
        return f"cves={stored} cpe_total={total}"
    finally:
        await engine.dispose()


@celery_app.task(name="cpe_sync")
def cpe_sync_task() -> str:
    return asyncio.run(_run())


@celery_app.task(name="nvd_backfill")
def nvd_backfill_task(days: int) -> str:
    """Tek seferlik GEÇMİŞ CVE/CPE yükleme (admin tetikler).

    Verilen ``days`` penceresi 120-günlük parçalara bölünüp NVD'den çekilir; CVE'ler ve
    CPE eşleşmeleri yerel indekse upsert edilir. Günlük ``cpe_sync`` penceresinden
    (``nvd_sync_days``) BAĞIMSIZDIR — onu değiştirmez; yalnız bir kez geniş çekim yapar.
    """
    return asyncio.run(_run(days=days, refresh_modified=False))
