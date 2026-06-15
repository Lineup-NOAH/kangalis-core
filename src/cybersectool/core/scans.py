"""Tarama (scan) işleri için servis fonksiyonları."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.core.models import Finding, Scan, ScanMode, ScanStatus, ScanType


async def create_scan(
    session: AsyncSession,
    scan_type: ScanType,
    target: str,
    created_by: int | None = None,
    mode: ScanMode = ScanMode.safe,
    categories: list[str] | None = None,
    batch_id: int | None = None,
    ports: str | None = None,
    assigned_user_id: int | None = None,
    notify_on_complete: bool = False,
    attach_report: bool = False,
    allow_external: bool = False,
    dir_scan: bool = False,
    wordlist_id: int | None = None,
    include_udp: bool = False,
) -> Scan:
    scan = Scan(
        scan_type=scan_type,
        target=target,
        created_by=created_by,
        mode=mode,
        categories=categories or [],
        batch_id=batch_id,
        ports=ports,
        assigned_user_id=assigned_user_id,
        notify_on_complete=notify_on_complete,
        attach_report=attach_report,
        allow_external=allow_external,
        dir_scan=dir_scan,
        wordlist_id=wordlist_id,
        include_udp=include_udp,
    )
    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    return scan


async def set_scan_status(
    session: AsyncSession,
    scan_id: int,
    status: ScanStatus,
    reason: str | None = None,
) -> Scan | None:
    scan = await session.get(Scan, scan_id)
    if scan is None:
        return None
    scan.status = status
    if status == ScanStatus.running and scan.started_at is None:
        scan.started_at = datetime.now(UTC)
    if status in (ScanStatus.completed, ScanStatus.failed):
        scan.finished_at = datetime.now(UTC)
    # Tamamlanan tarama HER ZAMAN %100 + anlamlı faz (görev progress yazmasa bile %0/
    # "Başlatılıyor"da takılı kalmasın — sca/kimlikli denetim/hardening gibi tüm türleri
    # tek noktadan kapsar). Çalışan ve fazı boş tarama "Çalışıyor" gösterir.
    if status == ScanStatus.completed:
        scan.progress = 100
        scan.phase = "Tamamlandı"
    elif status == ScanStatus.running and not scan.phase:
        scan.phase = "Çalışıyor"
    # Başarısızlık sebebini sakla (arayüzde gösterilir); başka durumlarda dokunma.
    if status == ScanStatus.failed and reason:
        scan.error_reason = reason[:255]
    await session.commit()
    await session.refresh(scan)
    return scan


async def set_scan_progress(
    session: AsyncSession, scan_id: int, progress: int, phase: str | None = None
) -> Scan | None:
    """Taramanın canlı ilerlemesini (0-100) ve faz metnini günceller."""
    scan = await session.get(Scan, scan_id)
    if scan is None:
        return None
    scan.progress = max(0, min(100, progress))
    if phase is not None:
        scan.phase = phase[:120]
    await session.commit()
    await session.refresh(scan)
    return scan


async def get_scan(session: AsyncSession, scan_id: int) -> Scan | None:
    return await session.get(Scan, scan_id)


async def delete_scan(session: AsyncSession, scan_id: int) -> bool:
    """Bir taramayı siler; bulguları da birlikte gider.

    Bulgular Postgres'te FK cascade ile zaten silinir; burada açıkça da
    siliyoruz ki FK uygulamayan ortamlarda (ör. SQLite) artık bulgu kalmasın.
    """
    scan = await session.get(Scan, scan_id)
    if scan is None:
        return False
    await session.execute(delete(Finding).where(Finding.scan_id == scan_id))
    await session.delete(scan)
    await session.commit()
    return True


async def list_scans(session: AsyncSession) -> list[Scan]:
    result = await session.execute(select(Scan).order_by(Scan.id.desc()))
    return list(result.scalars().all())


async def count_scans(session: AsyncSession) -> int:
    result = await session.execute(select(func.count()).select_from(Scan))
    return int(result.scalar_one() or 0)
