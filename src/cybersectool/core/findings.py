"""Bulgu (finding / zafiyet) için servis fonksiyonları."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.core.models import Finding, FindingStatus, Severity


async def create_finding(
    session: AsyncSession,
    scan_id: int,
    title: str,
    severity: Severity = Severity.info,
    asset_id: int | None = None,
    service_id: int | None = None,
    cve_id: str | None = None,
    risk_score: float | None = None,
    description: str | None = None,
    validated: bool = False,
) -> Finding:
    """Bir tarama bulgusu yazar — AYNI tarama içinde İDEMPOTENT.

    Aynı ``(scan_id, asset_id, service_id, cve_id, title)`` bulgu zaten varsa YENİSİ
    YAZILMAZ; mevcut döndürülür. Sebep: aynı CVE bir taramada birden çok kaynaktan eşleşebilir
    (yerel CPE bankası ``match_service_cves_offline`` + canlı NVD ``match_service_cves``) →
    eskiden her biri ayrı finding yazıyordu → raporda aynı CVE 2 kez ("76" şişkinliği). Başlık
    anahtara dahil olduğundan FARKLI başlıklı bulgular (ör. "EXPLOITED: …") ayrı kalır. Mevcut
    bulgunun ``validated`` bayrağı en iyiye yükseltilir (NSE-doğrulanmış > versiyon-çıkarımı).
    """
    existing = (
        await session.execute(
            select(Finding)
            .where(
                Finding.scan_id == scan_id,
                Finding.asset_id == asset_id,
                Finding.service_id == service_id,
                Finding.cve_id == cve_id,
                Finding.title == title,
            )
            .limit(1)
        )
    ).scalar_one_or_none()
    if existing is not None:
        if validated and not existing.validated:
            existing.validated = True
            await session.commit()
            await session.refresh(existing)
        return existing
    finding = Finding(
        scan_id=scan_id,
        title=title,
        severity=severity,
        asset_id=asset_id,
        service_id=service_id,
        cve_id=cve_id,
        risk_score=risk_score,
        description=description,
        validated=validated,
    )
    session.add(finding)
    await session.commit()
    await session.refresh(finding)
    return finding


async def list_findings(session: AsyncSession, severity: Severity | None = None) -> list[Finding]:
    stmt = select(Finding).order_by(Finding.id.desc())
    if severity is not None:
        stmt = stmt.where(Finding.severity == severity)
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def count_critical_for_scan(session: AsyncSession, scan_id: int) -> int:
    result = await session.execute(
        select(func.count())
        .select_from(Finding)
        .where(Finding.scan_id == scan_id, Finding.severity == Severity.critical)
    )
    return int(result.scalar_one() or 0)


async def count_open_findings(session: AsyncSession) -> int:
    result = await session.execute(
        select(func.count()).select_from(Finding).where(Finding.status == FindingStatus.open)
    )
    return int(result.scalar_one() or 0)


async def count_by_severity(session: AsyncSession, scan_id: int | None = None) -> dict[str, int]:
    """Açık bulguların severity dağılımını döndürür ({'critical': 4, ...}).

    scan_id verilirse yalnızca o taramanın bulgularını sayar.
    """
    stmt = (
        select(Finding.severity, func.count())
        .where(Finding.status == FindingStatus.open)
        .group_by(Finding.severity)
    )
    if scan_id is not None:
        stmt = stmt.where(Finding.scan_id == scan_id)
    result = await session.execute(stmt)
    counts: dict[str, int] = {}
    for row in result.all():
        severity, count = row
        counts[str(severity)] = int(count)
    return counts


async def count_findings_by_scan(session: AsyncSession) -> dict[int, int]:
    """Tarama başına toplam bulgu sayısı ({scan_id: count})."""
    result = await session.execute(select(Finding.scan_id, func.count()).group_by(Finding.scan_id))
    return {int(scan_id): int(count) for scan_id, count in result.all()}


async def list_findings_by_risk(
    session: AsyncSession,
    severity: Severity | None = None,
    limit: int | None = None,
    scan_id: int | None = None,
    scan_ids: list[int] | None = None,
) -> list[Finding]:
    """Bulguları risk skoruna (CVSS) göre azalan sırada listeler.

    scan_id verilirse yalnızca o taramanın bulguları döner (tarama-bazlı rapor).
    scan_ids verilirse bu tarama kümesinin bulguları döner (tarama işi/batch raporu).
    """
    stmt = select(Finding).order_by(Finding.risk_score.desc().nullslast(), Finding.id.desc())
    if severity is not None:
        stmt = stmt.where(Finding.severity == severity)
    if scan_id is not None:
        stmt = stmt.where(Finding.scan_id == scan_id)
    if scan_ids is not None:
        stmt = stmt.where(Finding.scan_id.in_(scan_ids))
    if limit is not None:
        stmt = stmt.limit(limit)
    result = await session.execute(stmt)
    return list(result.scalars().all())
