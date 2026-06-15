"""CVE/CPE bilgi bankası gezgini (salt-okuma) — ara · filtrele · sayfala.

Yerel ``cves`` (NVD backfill ile dolan) + ``cpe_matches`` tablolarını kullanıcıya
gezilebilir kılar. Exploit/Payload deposundan (``exploits`` tablosu, ``/exploits``)
AYRIDIR: burası "hangi zafiyetler var" bilgi bankası, orası sızma cephaneliği.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import ColumnElement, Select, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.core.cve_compliance import framework_db_signals
from cybersectool.core.models import CVE, CpeMatch, Severity

# Sayfa başına sonuç seçenekleri (büyük veri → sayfalama şart).
CVE_PER_PAGE_CHOICES: tuple[int, ...] = (25, 50, 100)

# "Ciddi" zafiyet (çekirdek uyum çerçeveleri için) — frameworks_for_cve ile birebir.
_SERIOUS = (Severity.critical, Severity.high)


def _cve_framework_clause(framework: str) -> ColumnElement[bool] | None:
    """CVE için uyum çerçevesi SQL koşulu — ``frameworks_for_cve`` ile birebir (drift yok).

    Anahtar kelimeler CVE açıklamasında aranır; çekirdek çerçeveler (KVKK/ISO/PCI) için
    ciddi olma (kritik/yüksek/KEV/CVSS>=7) koşulu eklenir. Eşleşme yoksa ``None``.
    """
    keywords, _categories, is_core = framework_db_signals(framework)
    conds: list[ColumnElement[bool]] = [CVE.description.ilike(f"%{kw}%") for kw in keywords]
    if is_core:
        conds.append(or_(CVE.severity.in_(_SERIOUS), CVE.kev_flag.is_(True), CVE.cvss_score >= 7.0))
    return or_(*conds) if conds else None


def _apply_filters(
    stmt: Select[Any],
    q: str | None,
    severity: Severity | None,
    kev_only: bool,
    framework: str | None,
    category: str | None,
) -> Select[Any]:
    """Ortak WHERE filtrelerini uygular (sayım + listeleme aynı kuralı kullansın)."""
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(CVE.cve_id.ilike(like), CVE.description.ilike(like)))
    if severity is not None:
        stmt = stmt.where(CVE.severity == severity)
    if kev_only:
        stmt = stmt.where(CVE.kev_flag.is_(True))
    if framework:
        clause = _cve_framework_clause(framework)
        if clause is not None:
            stmt = stmt.where(clause)
    if category:
        stmt = stmt.where(CVE.category == category)
    return stmt


async def count_cves_filtered(
    session: AsyncSession,
    *,
    q: str | None = None,
    severity: Severity | None = None,
    kev_only: bool = False,
    framework: str | None = None,
    category: str | None = None,
) -> int:
    """Filtreye uyan toplam CVE sayısı (sayfalama için)."""
    stmt = _apply_filters(
        select(func.count()).select_from(CVE), q, severity, kev_only, framework, category
    )
    return int((await session.execute(stmt)).scalar_one())


async def category_counts(session: AsyncSession) -> dict[str, int]:
    """Kategori başına CVE sayısı (``{kategori: adet}``) — Zafiyet DB kategori çipleri.

    Tek indexli GROUP BY (hızlı). NULL (sınıflanmamış) hariç tutulur.
    """
    stmt = (
        select(CVE.category, func.count()).where(CVE.category.is_not(None)).group_by(CVE.category)
    )
    return {str(cat): int(n) for cat, n in (await session.execute(stmt)).all() if cat}


async def list_cves_page(
    session: AsyncSession,
    *,
    q: str | None = None,
    severity: Severity | None = None,
    kev_only: bool = False,
    framework: str | None = None,
    category: str | None = None,
    page: int = 1,
    per: int = 50,
) -> list[CVE]:
    """Bir sayfa CVE döndürür (KEV önce, sonra CVSS azalan, sonra CVE id azalan)."""
    stmt = _apply_filters(select(CVE), q, severity, kev_only, framework, category)
    stmt = stmt.order_by(
        CVE.kev_flag.desc(),
        CVE.cvss_score.is_(None),  # önce CVSS'i olanlar (False/0 başa)
        CVE.cvss_score.desc(),
        CVE.cve_id.desc(),
    )
    stmt = stmt.offset(max(0, page - 1) * per).limit(per)
    return list((await session.execute(stmt)).scalars().all())


async def cpe_counts_for_cves(session: AsyncSession, cve_ids: list[str]) -> dict[str, int]:
    """Verilen CVE'ler için CPE eşleşme sayısı (``{cve_id: adet}``)."""
    if not cve_ids:
        return {}
    stmt = (
        select(CpeMatch.cve_id, func.count())
        .where(CpeMatch.cve_id.in_(cve_ids))
        .group_by(CpeMatch.cve_id)
    )
    return {str(cid): int(n) for cid, n in (await session.execute(stmt)).all()}
