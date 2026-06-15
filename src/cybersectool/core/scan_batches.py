"""Tarama işi (ScanBatch) servis fonksiyonları.

Sihirbazdan başlatılan çok hedefli tarama, tek isimli bir ScanBatch altında
gruplanır; raporlar bu batch'i tek satır gösterir, bulgular üye taramalardan
toplanır.
"""

from __future__ import annotations

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.core.models import Finding, Scan, ScanBatch, ScanMode, ScanStatus

QUICK_SCAN_PREFIX = "Hızlı tarama"


async def next_quick_scan_name(session: AsyncSession) -> str:
    """Boş bırakılan hızlı tarama için otomatik isim üretir: 'Hızlı tarama 1/2/3...'.

    Mevcut '{prefix} N' adlarındaki en büyük sayıyı bulur, bir fazlasını döndürür
    (DB-bağımsız: Python tarafında ayrıştırılır).
    """
    result = await session.execute(
        select(ScanBatch.name).where(ScanBatch.name.like(f"{QUICK_SCAN_PREFIX} %"))
    )
    max_num = 0
    for (name,) in result.all():
        tail = name[len(QUICK_SCAN_PREFIX) :].strip()
        if tail.isdigit():
            max_num = max(max_num, int(tail))
    return f"{QUICK_SCAN_PREFIX} {max_num + 1}"


async def create_batch(
    session: AsyncSession,
    name: str,
    mode: ScanMode = ScanMode.safe,
    categories: list[str] | None = None,
    created_by: int | None = None,
    assigned_user_id: int | None = None,
    notify_on_complete: bool = False,
    attach_report: bool = False,
) -> ScanBatch:
    batch = ScanBatch(
        name=name.strip() or "Adsız tarama",
        mode=mode,
        categories=categories or [],
        created_by=created_by,
        assigned_user_id=assigned_user_id,
        notify_on_complete=notify_on_complete,
        attach_report=attach_report,
    )
    session.add(batch)
    await session.commit()
    await session.refresh(batch)
    return batch


async def get_batch(session: AsyncSession, batch_id: int) -> ScanBatch | None:
    return await session.get(ScanBatch, batch_id)


async def delete_batch(session: AsyncSession, batch_id: int) -> bool:
    """Bir tarama işini (ScanBatch) ve üye taramaları/bulguları siler.

    Postgres'te FK cascade bunu kendiliğinden yapar; FK uygulamayan ortamlarda
    (ör. SQLite) artık satır kalmasın diye üye taramaların bulgularını ve
    taramalarını açıkça siliyoruz.
    """
    batch = await session.get(ScanBatch, batch_id)
    if batch is None:
        return False
    scan_ids = (
        (await session.execute(select(Scan.id).where(Scan.batch_id == batch_id))).scalars().all()
    )
    if scan_ids:
        await session.execute(delete(Finding).where(Finding.scan_id.in_(scan_ids)))
        await session.execute(delete(Scan).where(Scan.id.in_(scan_ids)))
    await session.delete(batch)
    await session.commit()
    return True


async def list_batches(session: AsyncSession) -> list[ScanBatch]:
    result = await session.execute(select(ScanBatch).order_by(ScanBatch.id.desc()))
    return list(result.scalars().all())


async def batch_scans(session: AsyncSession, batch_id: int) -> list[Scan]:
    """Bir batch'in üye taramalarını döndürür."""
    result = await session.execute(select(Scan).where(Scan.batch_id == batch_id).order_by(Scan.id))
    return list(result.scalars().all())


def batch_status(scans: list[Scan]) -> ScanStatus:
    """Üye taramaların durumundan batch'in genel durumunu çıkarır."""
    if not scans:
        return ScanStatus.pending
    statuses = {s.status for s in scans}
    if ScanStatus.running in statuses or ScanStatus.pending in statuses:
        return ScanStatus.running if ScanStatus.running in statuses else ScanStatus.pending
    if statuses == {ScanStatus.completed}:
        return ScanStatus.completed
    if ScanStatus.failed in statuses and ScanStatus.completed not in statuses:
        return ScanStatus.failed
    return ScanStatus.completed  # bazıları tamam bazıları başarısız → genel: tamamlandı


def batch_progress(scans: list[Scan]) -> int:
    """Üye taramaların ortalama ilerlemesi (0-100)."""
    if not scans:
        return 0
    return int(sum(s.progress for s in scans) / len(scans))


async def count_findings_by_batch(session: AsyncSession) -> dict[int, int]:
    """Batch başına toplam bulgu sayısı ({batch_id: sayı}) — üye taramaların bulguları."""
    result = await session.execute(
        select(Scan.batch_id, func.count(Finding.id))
        .join(Finding, Finding.scan_id == Scan.id)
        .where(Scan.batch_id.is_not(None))
        .group_by(Scan.batch_id)
    )
    return {int(bid): int(n) for bid, n in result.all() if bid is not None}
