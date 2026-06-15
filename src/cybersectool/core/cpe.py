"""Offline CPE eşleştirme — DB katmanı.

NVD'den çekilen CPE ölçütlerini yerel ``cpe_matches`` tablosuna yazar ve bir
servisi (nmap CPE'si üzerinden) ağ çağrısı olmadan yerel CVE'lerle eşleştirir.
"""

from __future__ import annotations

from typing import Any, cast

from sqlalchemy import CursorResult, delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.core.findings import create_finding
from cybersectool.core.models import CVE, CpeMatch, Service, Severity
from cybersectool.intel.cpe import (
    CpeMatchData,
    alias_candidates,
    cpe_match_applies,
    parse_cpe,
)


def _clip(value: str | None, limit: int) -> str | None:
    if value is None:
        return None
    return value[:limit]


async def store_cpe_matches(session: AsyncSession, cve_id: str, matches: list[CpeMatchData]) -> int:
    """Bir CVE'nin CPE ölçütlerini (yalnızca zafiyetli olanlar) idempotent yazar.

    Önce o CVE'ye ait eski satırları siler, sonra yenilerini ekler. Yazılan
    satır sayısını döndürür.
    """
    await session.execute(delete(CpeMatch).where(CpeMatch.cve_id == cve_id))
    written = 0
    for m in matches:
        if not m.vulnerable or not m.vendor or not m.product:
            continue
        session.add(
            CpeMatch(
                cve_id=cve_id[:30],
                part=_clip(m.part, 2) or "a",
                vendor=_clip(m.vendor, 128) or "",
                product=_clip(m.product, 128) or "",
                version=_clip(m.version, 128) or "*",
                vulnerable=True,
                version_start_including=_clip(m.version_start_including, 64),
                version_start_excluding=_clip(m.version_start_excluding, 64),
                version_end_including=_clip(m.version_end_including, 64),
                version_end_excluding=_clip(m.version_end_excluding, 64),
                criteria=_clip(m.criteria, 255) or "",
            )
        )
        written += 1
    await session.commit()
    return written


async def count_cpe_matches(session: AsyncSession) -> int:
    result = await session.execute(select(func.count()).select_from(CpeMatch))
    return int(result.scalar_one() or 0)


async def delete_cves(session: AsyncSession, cve_ids: list[str]) -> int:
    """Verilen CVE'leri + onlara ait CPE eşleşmelerini yerel depodan siler; silinen sayısını döner.

    Bir CVE NVD'de sonradan 'Rejected'a düşünce (geç-red) çağrılır: kayıt + ``cpe_matches`` kalırsa
    offline eşleştirme onu eşleştirmeye devam edip sahte bulgu üretir. Önce eşleşmeler, sonra CVE.
    """
    if not cve_ids:
        return 0
    await session.execute(delete(CpeMatch).where(CpeMatch.cve_id.in_(cve_ids)))
    result = await session.execute(delete(CVE).where(CVE.cve_id.in_(cve_ids)))
    await session.commit()
    return int(cast("CursorResult[Any]", result).rowcount or 0)


async def find_matching_cves(
    session: AsyncSession,
    vendor: str,
    product: str,
    service_version: str | None,
) -> list[str]:
    """(vendor, product) için yerel CPE ölçütlerini sürüm aralığına göre süzer.

    Eşleşen benzersiz cve_id listesini döndürür (ağ çağrısı yok).
    """
    result = await session.execute(
        select(CpeMatch).where(
            CpeMatch.vendor == vendor.lower(),
            CpeMatch.product == product.lower(),
        )
    )
    matched: dict[str, None] = {}  # sırayı koruyan benzersiz küme
    for row in result.scalars().all():
        data = CpeMatchData(
            criteria=row.criteria,
            part=row.part,
            vendor=row.vendor,
            product=row.product,
            version=row.version,
            vulnerable=row.vulnerable,
            version_start_including=row.version_start_including,
            version_start_excluding=row.version_start_excluding,
            version_end_including=row.version_end_including,
            version_end_excluding=row.version_end_excluding,
        )
        if cpe_match_applies(service_version, data):
            matched.setdefault(row.cve_id, None)
    return list(matched)


async def match_service_cves_offline(
    session: AsyncSession, scan_id: int, service: Service
) -> list[str]:
    """Servisi yerel CPE indeksiyle eşleştirir, Finding üretir; cve_id'leri döndürür.

    Öncelik nmap'in ``service.cpe``'sidir (örn. ``cpe:/a:apache:http_server:2.4.49``).
    CPE yoksa/eksikse servis banner ürün+adından **vendor-alias** ile aday türetilir
    (COV-4b: redis→redislabs, OpenSSH→openbsd, IIS→microsoft gibi vendor:product
    uyuşmazlıklarından kaynaklı kaçakları kapatır). Her aday yine sürüm-kapısından
    geçer; yalnız yerelde kaydı olan CVE'ler için bulgu üretir.
    """
    parsed = parse_cpe(service.cpe)
    if parsed is not None and parsed.vendor and parsed.product:
        base_vendor: str | None = parsed.vendor
        base_product: str | None = parsed.product
        # Sürüm: CPE'deki sürüm sürümsüz (*) ise servis bannerındaki sürüme düş.
        version = parsed.version
        if not version or version in {"*", "-"}:
            version = service.version or ""
    else:
        base_vendor = base_product = None  # CPE-yoksa fallback → yalnız alias adayları
        version = service.version or ""

    candidates = alias_candidates(base_vendor, base_product, service.product, service.service_name)
    if not candidates:
        return []

    # Tüm adaylardan eşleşen cve_id'leri sırayı koruyarak birleştir (tekrarsız).
    seen: set[str] = set()
    cve_ids: list[str] = []
    for cand_vendor, cand_product in candidates:
        for cve_id in await find_matching_cves(session, cand_vendor, cand_product, version):
            if cve_id not in seen:
                seen.add(cve_id)
                cve_ids.append(cve_id)

    label = service.product or base_product or candidates[0][1]
    matched: list[str] = []
    for cve_id in cve_ids:
        cve = await session.get(CVE, cve_id)
        if cve is None:
            continue  # offline: yerel CVE kaydı yoksa atla
        await create_finding(
            session,
            scan_id,
            title=f"{cve_id} — {label}",
            severity=cve.severity or Severity.info,
            asset_id=service.asset_id,
            service_id=service.id,
            cve_id=cve_id,
            risk_score=cve.cvss_score,
            description=cve.description,
        )
        matched.append(cve_id)
    return matched
