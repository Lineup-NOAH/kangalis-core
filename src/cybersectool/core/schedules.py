"""Zamanlanmış tarama (ScheduledScan) servis fonksiyonları."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.core.models import ScanMode, ScanType, ScheduledScan

# Sabit periyotların dakika karşılıkları ('interval' özel aralık kullanır).
PERIOD_MINUTES: dict[str, int] = {
    "daily": 1440,
    "weekly": 10080,
    "monthly": 43200,  # ~30 gün
}
PERIODS = ("daily", "weekly", "monthly", "once", "interval")


async def create_schedule(
    session: AsyncSession,
    scan_type: ScanType,
    target: str = "",
    period: str = "daily",
    interval_minutes: int = 1440,
    start_at: datetime | None = None,
    *,
    name: str = "",
    zone_ids: list[int] | None = None,
    asset_ids: list[int] | None = None,
    credential_zone_ids: list[int] | None = None,
    credential_ids: list[int] | None = None,
    mode: ScanMode = ScanMode.safe,
    categories: list[str] | None = None,
    created_by: int | None = None,
) -> ScheduledScan:
    """Zamanlanmış tarama oluşturur.

    İki kullanım: (1) tekil ``target`` (eski/legacy) ya da (2) sihirbazdan **batch
    şablonu** — ``zone_ids``/``asset_ids`` (+ opsiyonel kimlikler/mod/kategori). Zamanı
    gelince şablon, çoklu hedefli isimli bir batch'e dönüştürülerek başlatılır.
    """
    if period not in PERIODS:
        period = "daily"
    schedule = ScheduledScan(
        scan_type=scan_type,
        target=target,
        period=period,
        interval_minutes=max(1, interval_minutes),
        start_at=start_at,
        name=name,
        zone_ids=zone_ids or [],
        asset_ids=asset_ids or [],
        credential_zone_ids=credential_zone_ids or [],
        credential_ids=credential_ids or [],
        mode=mode,
        categories=categories or [],
        created_by=created_by,
    )
    session.add(schedule)
    await session.commit()
    await session.refresh(schedule)
    return schedule


def is_template(schedule: ScheduledScan) -> bool:
    """Şema batch-şablonu mu (sihirbazdan, çoklu hedef) yoksa tekil hedef mi?"""
    return bool(schedule.zone_ids or schedule.asset_ids)


def period_minutes(schedule: ScheduledScan) -> int:
    """Şemanın periyot dakikası ('interval' modunda interval_minutes)."""
    if schedule.period == "interval":
        return max(1, schedule.interval_minutes)
    return PERIOD_MINUTES.get(schedule.period, 1440)


async def list_schedules(session: AsyncSession) -> list[ScheduledScan]:
    result = await session.execute(select(ScheduledScan).order_by(ScheduledScan.id))
    return list(result.scalars().all())


async def get_schedule(session: AsyncSession, schedule_id: int) -> ScheduledScan | None:
    return await session.get(ScheduledScan, schedule_id)


async def delete_schedule(session: AsyncSession, schedule_id: int) -> bool:
    schedule = await session.get(ScheduledScan, schedule_id)
    if schedule is None:
        return False
    await session.delete(schedule)
    await session.commit()
    return True


async def set_schedule_active(session: AsyncSession, schedule_id: int, active: bool) -> bool:
    schedule = await session.get(ScheduledScan, schedule_id)
    if schedule is None:
        return False
    schedule.is_active = active
    await session.commit()
    return True


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def is_due(schedule: ScheduledScan, now: datetime) -> bool:
    """Zamanlanmış tarama şu an çalıştırılmalı mı?

    start_at verilmişse o ana kadar çalışmaz. 'once' tek sefer (last_run set
    olunca biter). Diğer periyotlar son çalışmadan beri periyot süresi geçince.
    """
    if not schedule.is_active:
        return False
    if schedule.start_at is not None and now < _as_utc(schedule.start_at):
        return False
    if schedule.period == "once":
        return schedule.last_run is None
    if schedule.last_run is None:
        return True
    return now - _as_utc(schedule.last_run) >= timedelta(minutes=period_minutes(schedule))


async def due_schedules(session: AsyncSession, now: datetime) -> list[ScheduledScan]:
    return [s for s in await list_schedules(session) if is_due(s, now)]
