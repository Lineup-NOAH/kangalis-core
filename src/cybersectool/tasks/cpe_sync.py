"""NVD CVE + CPE konfigürasyonlarını yerel depoya çeken Celery görevi.

Offline (ağsız) zafiyet eşleştirme için: bu görev CVE'leri ve CPE eşleşme
ölçütlerini ``cves`` / ``cpe_matches`` tablolarına yazar. Tarama anında artık
NVD'ye gidilmeden bu yerel indeksten eşleştirme yapılabilir.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable
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

    Verilen ``days`` penceresi 120-günlük parçalara bölünür ve **pencere-pencere** çekilir; her
    pencere bitince CVE/CPE yerel indekse upsert edilir, ilerleme Redis'e yazılır (Ayarlar sayfası
    canlı gösterir) ve **iptal bayrağı** yoklanır. Günlük ``cpe_sync`` penceresinden
    (``nvd_sync_days``) BAĞIMSIZDIR — onu değiştirmez; yalnız bir kez geniş çekim yapar.
    """
    return asyncio.run(_run_backfill(days))


async def _run_backfill(days: int) -> str:
    """Geçmiş CVE/CPE'yi pencere-pencere yükler; her pencerede ilerleme yazar + iptal yoklar.

    En yeni pencereden başlar (kullanıcı taze CVE'leri erken görür). Tek bir pencerenin ağ hatası
    tüm yüklemeyi düşürmez (o pencere atlanır). İptal istenirse o ana dek yazılan veri KORUNUR.
    """
    from cybersectool.core import cve_backfill as bf
    from cybersectool.intel.nvd import (
        NVD_PAGES_PER_WINDOW,
        backfill_windows,
        fetch_nvd_cve_window,
    )

    bf.reset_client()  # worker yeni event loop'ta → taze Redis istemcisi bu loop'ta kurulsun
    if not await bf.acquire():
        # Çift-dispatch yarışı: başka bir backfill zaten koşuyor → bu görev sessizce çekilir
        # (route'taki is_active guard'ının kaçırabileceği milisaniyelik yarışa atomik emniyet).
        await bf.aclose()
        return "skipped: already running"
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    windows = backfill_windows(days)
    years = max(1, round(days / 365))
    total_cves = 0
    cpe_total = 0
    final_status = "done"
    try:
        async with factory() as session:
            row = await get_settings(session)
            nvd_key = get_nvd_api_key(row) or None
        await bf.begin(windows_total=len(windows), years=years)
        for i, (win_start, win_end) in enumerate(windows):
            if await bf.is_cancelled():
                final_status = "cancelled"
                break
            try:
                cves = await fetch_nvd_cve_window(
                    win_start,
                    win_end,
                    max_pages=NVD_PAGES_PER_WINDOW,
                    api_key=nvd_key,
                    throttle_first=i > 0,  # ilk pencere hariç pencereler arası rate-limit boşluğu
                )
            except Exception:  # noqa: BLE001 — tek pencere hatası tüm backfill'i düşürmesin
                cves = []
            if cves:
                async with factory() as session:
                    for data in cves:
                        await upsert_cve(session, data)  # CVE + CPE ölçütleri (kendi içinde commit)
                        total_cves += 1
                    cpe_total = await count_cpe_matches(session)
            label = f"{win_start:%Y-%m-%d} – {win_end:%Y-%m-%d}"
            await bf.update(windows_done=i + 1, cves=total_cves, cpe_total=cpe_total, current=label)
        async with factory() as session:
            cpe_total = await count_cpe_matches(session)
            await record_cve_sync(session, datetime.now(UTC))
            await log_action(
                session,
                "nvd_backfill",
                target=f"durum={final_status} cve={total_cves} cpe={cpe_total} "
                f"pencere={len(windows)}",
            )
        await bf.finish(status=final_status, cves=total_cves, cpe_total=cpe_total)
        return f"status={final_status} cves={total_cves} cpe_total={cpe_total}"
    except Exception as exc:  # noqa: BLE001
        with contextlib.suppress(Exception):
            await bf.finish(
                status="error", cves=total_cves, cpe_total=cpe_total, error=str(exc)[:200]
            )
        raise
    finally:
        await bf.release()
        with contextlib.suppress(Exception):
            await engine.dispose()
        await bf.aclose()


async def build_cve_seed(
    *,
    start_year: int = 2000,
    batch: int = 1000,
    max_pages_per_window: int = 1000,
    on_window: Callable[[str], None] | None = None,
) -> str:
    """Maintainer: NVD'den GENİŞ tarihsel CVE/CPE çekimi (tohum/seed üretimi).

    ``start_year``-01-01'den bugüne 120-günlük pencerelere bölünür; her pencere TAM sayfalanır
    (tavan ``max_pages_per_window``), commit'ler ``batch`` kayıtta bir atılır (per-CVE commit
    yerine → ~yüz binlerce commit yerine birkaç bin → çok daha hızlı). NVD anahtarı DB ayarından
    çözülür (50 istek/30sn). UI backfill'inden AYRIDIR (Redis ilerleme/kilit YOK) — yalnızca tohum
    üretmek için; sonra ``export_cve_seed`` ile pg_dump alınır ve müşteriye import edilir.
    """
    from cybersectool.intel.nvd import backfill_windows, fetch_nvd_cve_window

    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as session:
            row = await get_settings(session)
            nvd_key = get_nvd_api_key(row) or None
        days = (datetime.now(UTC) - datetime(start_year, 1, 1, tzinfo=UTC)).days
        windows = backfill_windows(days)
        total = 0
        for wi, (win_start, win_end) in enumerate(windows, start=1):
            try:
                cves = await fetch_nvd_cve_window(
                    win_start,
                    win_end,
                    max_pages=max_pages_per_window,
                    api_key=nvd_key,
                    throttle_first=wi > 1,  # pencereler arası rate-limit boşluğu
                )
            except Exception:  # noqa: BLE001 — tek pencere hatası tüm çekimi düşürmesin
                cves = []
            if cves:
                async with factory() as session:
                    pending = 0
                    for data in cves:
                        await upsert_cve(session, data, commit=False)
                        total += 1
                        pending += 1
                        if pending >= batch:
                            await session.commit()  # toplu commit (per-CVE değil)
                            pending = 0
                    await session.commit()
            if on_window is not None:
                on_window(
                    f"[{wi}/{len(windows)}] {win_start:%Y-%m-%d}..{win_end:%Y-%m-%d} "
                    f"+{len(cves)} (toplam {total})"
                )
        async with factory() as session:
            cpe_total = await count_cpe_matches(session)
            await record_cve_sync(session, datetime.now(UTC))
        return f"done cves~={total} cpe_total={cpe_total} windows={len(windows)}"
    finally:
        await engine.dispose()
