"""Zafiyet yaşam döngüsü: Finding kanıtlarından tekilleştirilmiş Vulnerability durumu."""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.core.models import (
    Asset,
    Finding,
    FindingStatus,
    Scan,
    ScanType,
    Severity,
    Vulnerability,
)
from cybersectool.core.vuln_category import WEAK_CREDENTIAL, derive_vuln_category


# Oto-çözüm domain izolasyonu: bir web taraması ağ zafiyetini çözmemeli.
def scan_domain(scan_type: ScanType) -> str:
    if scan_type == ScanType.web:
        return "web"
    if scan_type == ScanType.sca:
        return "sca"
    if scan_type == ScanType.credentialed:
        return "credentialed"
    if scan_type == ScanType.hardening:
        return "hardening"
    return "network"  # network + vuln → aynı domain (ikisi de nmap servis-CVE)


# Başlıktaki parantezli oynak kısımları (ör. "(HTTP 403)") fingerprint'ten çıkar →
# aynı zafiyetin durum-kodu değişince kopya/yeniden-açılma churn'ü olmaz (H1).
_PARENS = re.compile(r"\([^)]*\)")


def normalize_title(title: str) -> str:
    return " ".join(_PARENS.sub("", title).lower().split())


def finding_fingerprint(cve_id: str | None, title: str, service_id: int | None) -> str:
    """Tekil kimlik: CVE varsa CVE; yoksa normalize(başlık)+servis."""
    if cve_id:
        return f"cve:{cve_id}"
    svc = f":svc{service_id}" if service_id is not None else ""
    return f"title:{normalize_title(title)}{svc}"


def _coverage_rank(scan: Scan) -> int:
    """Tarama port-kapsamı sıralaması: 2=tüm portlar, 1=top/varsayılan, 0=elle liste."""
    p = (scan.ports or "").strip().lower()
    if p == "all":
        return 2
    if p in ("", "top"):
        return 1
    return 0  # elle port listesi = kısmi kapsam


def _as_aware(dt: datetime) -> datetime:
    """Naive datetime'ı UTC kabul ederek aware'e çevir (sqlite naive döndürür)."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


async def _covered_asset_ids(
    session: AsyncSession, scan: Scan, finding_asset_ids: list[int]
) -> set[int]:
    """Taramanın gerçekten ERİŞTİĞİ varlık id'leri.

    Bulgusu olan varlık kesin tarandı. Ek olarak, hedef IP/CIDR içindeki varlıklardan
    YALNIZCA bu taramada erişilenler (up host → tarama `upsert_asset` ile ``last_seen``
    bump eder; kapalı host stale kalır) eklenir. Bu, /24 taramasında kapalı bir host'un
    hâlâ açık zafiyetlerinin yanlışlıkla 'giderildi'ye düşmesini engeller (C1).
    """
    ids: set[int] = set(finding_asset_ids)
    target = (scan.target or "").strip()
    if scan.started_at is None:
        return ids  # erişim sinyali yok → yalnızca bulgulu varlıklar
    try:
        net = ipaddress.ip_network(target, strict=False)  # tek IP = /32, CIDR de olur
    except ValueError:
        return ids  # hedef IP/CIDR değil (URL/hostname) → sadece bulgulardan
    started = _as_aware(scan.started_at)
    assets = (await session.execute(select(Asset))).scalars().all()
    for a in assets:
        if a.ip is None:
            continue  # URL varlığı → IP/CIDR kapsamına girmez
        try:
            in_net = ipaddress.ip_address(a.ip) in net
        except ValueError:
            continue
        if in_net and a.last_seen is not None and _as_aware(a.last_seen) >= started:
            ids.add(a.id)  # bu taramada erişilen (up) host
    return ids


async def sync_vulnerabilities_for_scan(session: AsyncSession, scan_id: int) -> dict[str, int]:
    """Tarama bitince Finding'leri Vulnerability'ye işler (upsert + oto-çözüm/reopen).

    - Her finding → (asset_id, fingerprint) upsert; varsa last_seen güncelle, KOPYA YOK.
    - resolved bir vuln tekrar görülürse → reopened (status=open, reopened_count+1).
    - Manuel triyaj (accepted_risk/false_positive/confirmed) tekrar görülünce KORUNUR.
    - Oto-çözüm: SADECE ``open`` vuln'lar, elle-port DIŞI (top/tüm) tarama + AYNI domain +
      bu taramada gerçekten ERİŞİLEN varlık için, bu taramada görünmeyenleri resolved'a
      alır. ``confirmed`` (analist doğruladı) oto-çözülmez. Daha GENİŞ kapsamda görülmüş
      vuln, daha DAR taramayla çözülmez (coverage guard → yanlış-çözme koruması).
    Döner: {"upserted", "resolved", "reopened"}.
    """
    scan = await session.get(Scan, scan_id)
    if scan is None:
        return {"upserted": 0, "resolved": 0, "reopened": 0}
    rank = _coverage_rank(scan)
    findings = list(
        (await session.execute(select(Finding).where(Finding.scan_id == scan_id))).scalars().all()
    )
    now = datetime.now(UTC)
    seen_by_asset: dict[int, set[str]] = defaultdict(set)
    upserted = reopened = 0
    for f in findings:
        if f.asset_id is None:
            continue
        fp = finding_fingerprint(f.cve_id, f.title, f.service_id)
        seen_by_asset[f.asset_id].add(fp)
        existing = (
            await session.execute(
                select(Vulnerability).where(
                    Vulnerability.asset_id == f.asset_id,
                    Vulnerability.fingerprint == fp,
                )
            )
        ).scalar_one_or_none()
        category = derive_vuln_category(f.title, scan.scan_type, f.cve_id)
        if existing is None:
            session.add(
                Vulnerability(
                    asset_id=f.asset_id,
                    fingerprint=fp,
                    scan_type=scan.scan_type,
                    title=f.title,
                    severity=f.severity,
                    cve_id=f.cve_id,
                    risk_score=f.risk_score,
                    status=FindingStatus.open,
                    first_seen=now,
                    last_seen=now,
                    last_scan_id=scan_id,
                    coverage=rank,
                    validated=f.validated,
                    category=category,
                )
            )
            upserted += 1
        else:
            existing.last_seen = now
            existing.last_scan_id = scan_id
            existing.scan_type = scan.scan_type
            existing.title = f.title
            existing.severity = f.severity
            existing.cve_id = f.cve_id
            existing.risk_score = f.risk_score
            existing.coverage = rank
            existing.category = category
            # Doğrulama yapışkan: bir kez aktif doğrulandıysa öyle kalır (VI-13).
            existing.validated = existing.validated or f.validated
            if existing.status == FindingStatus.resolved:
                existing.status = FindingStatus.open
                existing.resolved_at = None
                existing.reopened_count += 1
                reopened += 1
            upserted += 1

    # --- Oto-çözüm (yanlış-çözme korumalı) ---
    resolved = 0
    if rank >= 1:  # elle-port taraması (kısmi kapsam) HİÇBİR ŞEY çözmez
        covered = await _covered_asset_ids(session, scan, list(seen_by_asset.keys()))
        domain = scan_domain(scan.scan_type)
        for asset_id in covered:
            seen = seen_by_asset.get(asset_id, set())
            vulns = list(
                (
                    await session.execute(
                        select(Vulnerability).where(
                            Vulnerability.asset_id == asset_id,
                            Vulnerability.status == FindingStatus.open,
                        )
                    )
                )
                .scalars()
                .all()
            )
            for v in vulns:
                if v.category == WEAK_CREDENTIAL:
                    # Zayıf/varsayılan kimlik bulguları OTO-ÇÖZÜLMEZ (yalnız manuel triyaj).
                    # Aksi halde örn. bir SMB denetimi, aynı asset'teki brute-force zayıf-kimlik
                    # bulgusunu (kimliği gerçekten test etmeden) yanlışlıkla 'giderildi' yapardı.
                    continue
                if scan_domain(v.scan_type) != domain:
                    continue  # farklı domain → dokunma (web ağ vuln'ünü çözmesin)
                if v.coverage > rank:
                    continue  # daha geniş kapsamda görülmüş → dar tarama çözemez (C2)
                if v.fingerprint not in seen:
                    v.status = FindingStatus.resolved
                    v.resolved_at = now
                    resolved += 1
    await session.commit()  # upsert + oto-çözüm tek transaction (M2)
    return {"upserted": upserted, "resolved": resolved, "reopened": reopened}


# --- sorgu/triyaj (V3 sayfası kullanacak) ---
async def get_vulnerability(session: AsyncSession, vuln_id: int) -> Vulnerability | None:
    return await session.get(Vulnerability, vuln_id)


async def list_vulnerabilities(
    session: AsyncSession,
    *,
    resolved: bool | None = None,
    severity: Severity | None = None,
    asset_id: int | None = None,
    limit: int | None = None,
    offset: int | None = None,
) -> list[Vulnerability]:
    stmt = select(Vulnerability)
    if resolved is True:
        stmt = stmt.where(Vulnerability.status == FindingStatus.resolved)
    elif resolved is False:
        stmt = stmt.where(Vulnerability.status != FindingStatus.resolved)
    if severity is not None:
        stmt = stmt.where(Vulnerability.severity == severity)
    if asset_id is not None:
        stmt = stmt.where(Vulnerability.asset_id == asset_id)
    stmt = stmt.order_by(
        Vulnerability.risk_score.desc().nullslast(), Vulnerability.last_seen.desc()
    )
    if offset is not None:
        stmt = stmt.offset(offset)
    if limit is not None:
        stmt = stmt.limit(limit)
    return list((await session.execute(stmt)).scalars().all())


async def list_vulnerabilities_page(
    session: AsyncSession,
    *,
    resolved: bool,
    per: int,
    page: int,
    category: str | None = None,
) -> list[Vulnerability]:
    """Sayfalanmış liste, VARLIĞA göre gruplanabilir biçimde sıralı (asset_id, risk).

    ``category`` verilirse (ör. ``weak_credential``) yalnız o kategori filtrelenir.
    """
    offset = max(0, (page - 1) * per)
    stmt = select(Vulnerability)
    if resolved:
        stmt = stmt.where(Vulnerability.status == FindingStatus.resolved)
    else:
        stmt = stmt.where(Vulnerability.status != FindingStatus.resolved)
    if category:
        stmt = stmt.where(Vulnerability.category == category)
    stmt = (
        stmt.order_by(
            Vulnerability.asset_id.asc(),
            Vulnerability.risk_score.desc().nullslast(),
            Vulnerability.severity.asc(),
            Vulnerability.id.asc(),
        )
        .offset(offset)
        .limit(per)
    )
    return list((await session.execute(stmt)).scalars().all())


async def severity_counts_by_asset(
    session: AsyncSession, *, resolved: bool
) -> dict[int, dict[str, int]]:
    """{asset_id: {severity: adet}} — grup başlıklarındaki severity rozetleri için."""
    stmt = select(Vulnerability.asset_id, Vulnerability.severity, func.count()).group_by(
        Vulnerability.asset_id, Vulnerability.severity
    )
    if resolved:
        stmt = stmt.where(Vulnerability.status == FindingStatus.resolved)
    else:
        stmt = stmt.where(Vulnerability.status != FindingStatus.resolved)
    out: dict[int, dict[str, int]] = {}
    for asset_id, sev, cnt in (await session.execute(stmt)).all():
        out.setdefault(asset_id, {})[sev.value if hasattr(sev, "value") else sev] = int(cnt)
    return out


async def count_vulnerabilities(
    session: AsyncSession, *, resolved: bool | None = None, category: str | None = None
) -> int:
    stmt = select(func.count()).select_from(Vulnerability)
    if resolved is True:
        stmt = stmt.where(Vulnerability.status == FindingStatus.resolved)
    elif resolved is False:
        stmt = stmt.where(Vulnerability.status != FindingStatus.resolved)
    if category:
        stmt = stmt.where(Vulnerability.category == category)
    return int((await session.execute(stmt)).scalar_one())


async def category_counts(session: AsyncSession, *, resolved: bool) -> dict[str, int]:
    """{kategori: adet} — Zafiyetler sayfası kategori filtre çiplerinin sayıları."""
    stmt = select(Vulnerability.category, func.count()).group_by(Vulnerability.category)
    if resolved:
        stmt = stmt.where(Vulnerability.status == FindingStatus.resolved)
    else:
        stmt = stmt.where(Vulnerability.status != FindingStatus.resolved)
    out: dict[str, int] = {}
    for cat, cnt in (await session.execute(stmt)).all():
        out[cat or "other"] = int(cnt)
    return out


async def severity_counts_open(session: AsyncSession, *, resolved: bool = False) -> dict[str, int]:
    """{severity: adet} — panel önem dağılımı (varsayılan: açık zafiyetler)."""
    stmt = select(Vulnerability.severity, func.count()).group_by(Vulnerability.severity)
    if resolved:
        stmt = stmt.where(Vulnerability.status == FindingStatus.resolved)
    else:
        stmt = stmt.where(Vulnerability.status != FindingStatus.resolved)
    out: dict[str, int] = {}
    for sev, cnt in (await session.execute(stmt)).all():
        out[sev.value if hasattr(sev, "value") else sev] = int(cnt)
    return out


async def vuln_lifecycle_stats(session: AsyncSession) -> dict[str, int | float | None]:
    """Panel için zafiyet yaşam-döngüsü özeti (açık/çözülen/yeni/MTTR vb.).

    Cross-db güvenli: minimal kolonları yükler, zaman pencerelerini Python'da
    (``_as_aware`` ile) hesaplar — sqlite naive vs Postgres aware string-karşılaştırma
    tuzağına düşmez. Döner: open/resolved/new_7d/resolved_7d/regressions/aging_30d/mttr_days.
    """
    now = datetime.now(UTC)
    week_ago = now - timedelta(days=7)
    month_ago = now - timedelta(days=30)
    rows = (
        await session.execute(
            select(
                Vulnerability.first_seen,
                Vulnerability.resolved_at,
                Vulnerability.status,
                Vulnerability.reopened_count,
            )
        )
    ).all()
    open_count = resolved_count = new_7d = resolved_7d = regressions = aging_30d = 0
    mttr_total = 0.0
    mttr_n = 0
    for first_seen, resolved_at, status, reopened in rows:
        fs = _as_aware(first_seen) if first_seen is not None else None
        ra = _as_aware(resolved_at) if resolved_at is not None else None
        if status == FindingStatus.resolved:
            resolved_count += 1
            if ra is not None and ra >= week_ago:
                resolved_7d += 1
            if ra is not None and fs is not None and ra >= fs:
                mttr_total += (ra - fs).total_seconds()
                mttr_n += 1
        else:
            open_count += 1
            if fs is not None and fs >= week_ago:
                new_7d += 1
            if fs is not None and fs <= month_ago:
                aging_30d += 1
            if reopened and reopened > 0:
                regressions += 1
    mttr_days = round(mttr_total / mttr_n / 86400, 1) if mttr_n else None
    return {
        "open": open_count,
        "resolved": resolved_count,
        "new_7d": new_7d,
        "resolved_7d": resolved_7d,
        "regressions": regressions,
        "aging_30d": aging_30d,
        "mttr_days": mttr_days,
    }


async def vuln_trend(session: AsyncSession, *, weeks: int = 8) -> dict[str, object]:
    """Haftalık zafiyet trendi — first_seen/resolved_at'ten türetilir (anlık-görüntü tablosu YOK).

    Bir zafiyet ``[first_seen, resolved_at)`` aralığında AÇIKtır; bu sayede geçmiş herhangi
    bir andaki açık sayısı yeniden kurulabilir. Cross-db güvenli (minimal kolon + Python).

    Döner:
      points: [{label, open, new, resolved}] (eski→yeni, ``weeks`` adet haftalık kova)
      aging:  {fresh(≤7g), recent(8-30g), old(>30g)}  (şu an açık olanlar)
      mttr_days, open_total, resolved_total
    """
    now = datetime.now(UTC)
    rows = (
        await session.execute(
            select(
                Vulnerability.first_seen,
                Vulnerability.resolved_at,
                Vulnerability.status,
            )
        )
    ).all()
    spans: list[tuple[datetime, datetime | None, bool]] = []
    mttr_total = 0.0
    mttr_n = 0
    open_total = resolved_total = 0
    fresh = recent = old = 0
    for first_seen, resolved_at, status in rows:
        fs = _as_aware(first_seen) if first_seen is not None else now
        ra = _as_aware(resolved_at) if resolved_at is not None else None
        is_resolved = status == FindingStatus.resolved
        spans.append((fs, ra if is_resolved else None, is_resolved))
        if is_resolved:
            resolved_total += 1
            if ra is not None and ra >= fs:
                mttr_total += (ra - fs).total_seconds()
                mttr_n += 1
        else:
            open_total += 1
            age_days = (now - fs).days
            if age_days <= 7:
                fresh += 1
            elif age_days <= 30:
                recent += 1
            else:
                old += 1

    def _open_at(t: datetime) -> int:
        return sum(1 for fs, ra, _ in spans if fs <= t and (ra is None or ra > t))

    points: list[dict[str, object]] = []
    for i in range(weeks - 1, -1, -1):
        w_end = now - timedelta(days=7 * i)
        w_start = w_end - timedelta(days=7)
        new_n = sum(1 for fs, _, _ in spans if w_start <= fs < w_end)
        res_n = sum(1 for _, ra, _ in spans if ra is not None and w_start <= ra < w_end)
        points.append(
            {
                "label": w_end.strftime("%m-%d"),
                "open": _open_at(w_end),
                "new": new_n,
                "resolved": res_n,
            }
        )
    mttr_days = round(mttr_total / mttr_n / 86400, 1) if mttr_n else None
    return {
        "points": points,
        "aging": {"fresh": fresh, "recent": recent, "old": old},
        "mttr_days": mttr_days,
        "open_total": open_total,
        "resolved_total": resolved_total,
    }


async def set_vuln_status(
    session: AsyncSession,
    vuln_id: int,
    status: FindingStatus,
    *,
    note: str | None = None,
    user_id: int | None = None,
) -> bool:
    """Manuel triyaj: durum + not. resolved'a alınınca resolved_at set, aksi halde temizle."""
    v = await session.get(Vulnerability, vuln_id)
    if v is None:
        return False
    v.status = status
    if note is not None:
        v.note = note
    v.updated_by = user_id
    v.resolved_at = datetime.now(UTC) if status == FindingStatus.resolved else None
    await session.commit()
    return True
