"""Zamanlanmış tarama: due mantığı + dispatch testleri."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.models import ScanType, ScheduledScan
from cybersectool.core.schedules import (
    create_schedule,
    delete_schedule,
    get_schedule,
    is_due,
    period_minutes,
    set_schedule_active,
)
from cybersectool.tasks import scheduled
from cybersectool.tasks.celery_app import celery_app


def test_is_due() -> None:
    now = datetime.now(UTC)
    sched = ScheduledScan(
        scan_type=ScanType.network,
        target="x",
        period="interval",
        interval_minutes=60,
        is_active=True,
        last_run=None,
    )
    assert is_due(sched, now) is True  # hiç çalışmadı → due

    sched.last_run = now
    assert is_due(sched, now) is False  # az önce → değil

    sched.last_run = now - timedelta(minutes=120)
    assert is_due(sched, now) is True  # eski → due

    sched.is_active = False
    sched.last_run = None
    assert is_due(sched, now) is False  # pasif → değil


def test_period_minutes() -> None:
    def s(period: str, interval: int = 1440) -> ScheduledScan:
        return ScheduledScan(
            scan_type=ScanType.network, target="x", period=period, interval_minutes=interval
        )

    assert period_minutes(s("daily")) == 1440
    assert period_minutes(s("weekly")) == 10080
    assert period_minutes(s("monthly")) == 43200
    assert period_minutes(s("interval", 15)) == 15


def test_is_due_once() -> None:
    now = datetime.now(UTC)
    sched = ScheduledScan(
        scan_type=ScanType.network, target="x", period="once", is_active=True, last_run=None
    )
    assert is_due(sched, now) is True  # henüz çalışmadı
    sched.last_run = now - timedelta(days=400)
    assert is_due(sched, now) is False  # tek sefer çalıştı → bir daha değil


def test_is_due_start_at_in_future() -> None:
    now = datetime.now(UTC)
    sched = ScheduledScan(
        scan_type=ScanType.network,
        target="x",
        period="daily",
        is_active=True,
        last_run=None,
        start_at=now + timedelta(hours=2),
    )
    assert is_due(sched, now) is False  # başlangıç gelecekte → çalışmaz


def test_is_due_weekly() -> None:
    now = datetime.now(UTC)
    sched = ScheduledScan(scan_type=ScanType.network, target="x", period="weekly", is_active=True)
    sched.last_run = now - timedelta(days=3)
    assert is_due(sched, now) is False  # 3 gün < 7
    sched.last_run = now - timedelta(days=8)
    assert is_due(sched, now) is True  # 8 gün ≥ 7


async def test_schedule_crud(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        sched = await create_schedule(session, ScanType.network, "10.0.0.0/24", interval_minutes=60)
        assert await get_schedule(session, sched.id) is not None
        # Pasifleştir
        assert await set_schedule_active(session, sched.id, False) is True
        fetched = await get_schedule(session, sched.id)
        assert fetched is not None and fetched.is_active is False
        # Sil
        assert await delete_schedule(session, sched.id) is True
        assert await get_schedule(session, sched.id) is None
        assert await delete_schedule(session, sched.id) is False


def test_beat_schedule_configured() -> None:
    assert "check-scheduled-scans" in celery_app.conf.beat_schedule
    # Exploit DB günlük otomatik tazelenir
    assert "exploit-db-sync" in celery_app.conf.beat_schedule
    assert celery_app.conf.beat_schedule["exploit-db-sync"]["task"] == "exploit_sync"


async def test_dispatch_due(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    enqueued: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        scheduled.network_scan_task, "delay", lambda *args, **kwargs: enqueued.append(args)
    )
    async with session_factory() as session:
        await create_schedule(session, ScanType.network, "10.0.0.0/24", interval_minutes=60)
        count = await scheduled.dispatch_due(session, datetime.now(UTC))
        assert count == 1
        assert len(enqueued) == 1
        # hemen tekrar → last_run yeni, due değil
        assert await scheduled.dispatch_due(session, datetime.now(UTC)) == 0


async def test_dispatch_due_template(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Batch-şablonu zamanlama: zone'dan çoklu hedef → isimli batch + kuyruğa alma."""
    from cybersectool.core.models import ScopePolicy
    from cybersectool.core.scan_batches import list_batches
    from cybersectool.core.zones import create_zone

    enqueued: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        scheduled.network_scan_task, "delay", lambda *args, **kwargs: enqueued.append(args)
    )
    async with session_factory() as session:
        session.add(
            ScopePolicy(name="s", allowed_cidrs=["10.0.0.0/24"], denied_cidrs=[], is_active=True)
        )
        await session.commit()
        zone = await create_zone(session, "Z", ["10.0.0.5", "10.0.0.6"])
        await create_schedule(
            session,
            ScanType.network,
            name="Haftalık batch",
            zone_ids=[zone.id],
            interval_minutes=60,
        )
        count = await scheduled.dispatch_due(session, datetime.now(UTC))
        assert count == 1
        batches = await list_batches(session)
        assert batches and batches[0].name == "Haftalık batch"
        # Birleşik tarama: zone'daki iki hedef TEK taramada birleşir (zone=tek tarama).
        assert len(enqueued) == 1
        target_arg = enqueued[0][1]
        assert "10.0.0.5" in target_arg and "10.0.0.6" in target_arg


async def test_dispatch_due_template_no_orphan_batch(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Tüm hedefler kapsam dışıysa şablon zamanlaması boş (orphan) batch bırakmaz (W7)."""
    from cybersectool.core.models import ScopePolicy
    from cybersectool.core.scan_batches import list_batches
    from cybersectool.core.zones import create_zone

    monkeypatch.setattr(scheduled.network_scan_task, "delay", lambda *args, **kwargs: None)
    async with session_factory() as session:
        session.add(
            ScopePolicy(name="s", allowed_cidrs=["10.0.0.0/24"], denied_cidrs=[], is_active=True)
        )
        await session.commit()
        zone = await create_zone(session, "out", ["192.168.99.0/24"])  # kapsam dışı
        await create_schedule(
            session, ScanType.network, name="orphan-test", zone_ids=[zone.id], interval_minutes=60
        )
        count = await scheduled.dispatch_due(session, datetime.now(UTC))
        assert count == 1  # zamanlama tetiklendi (last_run set)
        assert await list_batches(session) == []  # ama hiç tarama yok → orphan batch yok
