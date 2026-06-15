"""Zamanlanmış taramaları periyodik kontrol eden Celery görevi (Celery beat tetikler)."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from cybersectool.config import settings
from cybersectool.core.assets import get_asset
from cybersectool.core.credentials import (
    credentials_in_zone,
    get_credential,
    get_credential_zone,
)
from cybersectool.core.models import Credential, ScanType, ScheduledScan
from cybersectool.core.scan_batches import batch_scans, create_batch, delete_batch
from cybersectool.core.scans import create_scan
from cybersectool.core.schedules import due_schedules, is_template
from cybersectool.core.zones import get_zone
from cybersectool.dispatch import (
    audit_credentialed_to_scan,
    dispatch_ping_scan,
    dispatch_target_list_scan,
)
from cybersectool.tasks.celery_app import celery_app
from cybersectool.tasks.network_scan import network_scan_task
from cybersectool.tasks.web_scan import web_scan_task


async def _dispatch_template(session: AsyncSession, schedule: ScheduledScan) -> None:
    """Batch-şablonu zamanlamayı çoklu hedefli isimli bir batch'e çevirip başlatır."""
    targets: list[str] = []
    for zid in schedule.zone_ids:
        zone = await get_zone(session, zid)
        if zone is not None:
            targets.extend(zone.cidrs)
    for aid in schedule.asset_ids:
        asset = await get_asset(session, aid)
        if asset is not None:
            tgt = asset.url or asset.ip  # URL varlığı → URL hedef; IP varlığı → IP
            if tgt:
                targets.append(tgt)
    targets = list(dict.fromkeys(targets))
    if not targets:
        return

    creds: list[Credential] = []
    seen: set[int] = set()
    for czid in schedule.credential_zone_ids:
        cz = await get_credential_zone(session, czid)
        if cz is not None:
            for cred in await credentials_in_zone(session, cz):
                if cred.id not in seen:
                    seen.add(cred.id)
                    creds.append(cred)
    for cid in schedule.credential_ids:
        single = await get_credential(session, cid)
        if single is not None and single.id not in seen:
            seen.add(single.id)
            creds.append(single)

    batch_name = schedule.name or f"Zamanlı tarama {schedule.id}"
    batch = await create_batch(
        session, batch_name, schedule.mode, schedule.categories, schedule.created_by
    )
    if schedule.scan_type == ScanType.ping:
        # Ping şablonu: host keşfi (mod/kategori/kimlik yok sayılır).
        await dispatch_ping_scan(
            session, targets, schedule.created_by, label="zamanlı", batch_id=batch.id
        )
    else:
        # Ağ / Güvenli CVE / Agresif CVE — scan_type + nmap modu şablondan taşınır.
        net_res = await dispatch_target_list_scan(
            session,
            targets,
            schedule.mode,
            schedule.created_by,
            label="zamanlı",
            categories=schedule.categories,
            batch_id=batch.id,
            scan_type=schedule.scan_type,
        )
        # NESSUS modeli: kimlik şablona dahilse AYNI taramaya içeriden kimlikli denetim eklenir
        # (ayrı satır açılmaz). Zamanlı taramada priv-esc DENEMESİ yapılmaz — yalnız enum.
        if creds and net_res.scans:
            await audit_credentialed_to_scan(
                session,
                net_res.scans[0].id,
                targets,
                creds,
                user_id=schedule.created_by,
            )
    # Tüm hedefler kapsam dışıysa hiç tarama oluşmaz → boş batch'i sil (orphan önle).
    if not await batch_scans(session, batch.id):
        await delete_batch(session, batch.id)


async def dispatch_due(session: AsyncSession, now: datetime) -> int:
    """Zamanı gelen taramaları oluşturur + kuyruğa alır, last_run günceller."""
    due = await due_schedules(session, now)
    for schedule in due:
        if is_template(schedule):
            await _dispatch_template(session, schedule)
        else:
            scan = await create_scan(session, schedule.scan_type, schedule.target)
            if schedule.scan_type == ScanType.web:
                web_scan_task.delay(scan.id, schedule.target)
            else:
                network_scan_task.delay(scan.id, schedule.target)
        schedule.last_run = now
    await session.commit()
    return len(due)


async def _run() -> int:
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as session:
            return await dispatch_due(session, datetime.now(UTC))
    finally:
        await engine.dispose()


@celery_app.task(name="check_scheduled_scans")
def check_scheduled_scans_task() -> str:
    return f"dispatched:{asyncio.run(_run())}"
