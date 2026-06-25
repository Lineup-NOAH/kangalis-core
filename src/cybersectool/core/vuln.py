"""Zafiyet eşleştirme: servis → CVE (NVD) → Finding."""

from __future__ import annotations

import re

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.core.cpe import store_cpe_matches
from cybersectool.core.exploit_classify import primary_category
from cybersectool.core.exploits import exploit_summary_for_cves
from cybersectool.core.findings import create_finding
from cybersectool.core.models import CVE, Finding, Service, Severity, Vulnerability
from cybersectool.core.risk import compute_priority, exploit_level_from_hit
from cybersectool.intel.cpe import cpe_match_applies
from cybersectool.intel.epss import fetch_epss
from cybersectool.intel.kev import fetch_kev_set
from cybersectool.intel.nvd import CveData, fetch_cves


async def count_cves(session: AsyncSession) -> int:
    """Yerel CVE deposundaki toplam CVE sayısı (senkron kapsam göstergesi)."""
    result = await session.execute(select(func.count()).select_from(CVE))
    return int(result.scalar_one())


async def upsert_cve(session: AsyncSession, data: CveData, *, commit: bool = True) -> CVE:
    """Bir CVE'yi (ve CPE ölçütlerini) yerel depoya yazar.

    ``commit=False`` ise commit YAPILMAZ — toplu yükleme (backfill/seed üretimi) çağıranı
    her N kayıtta bir tek commit atarak ~yüz binlerce tekil commit'in maliyetinden kurtulur.
    Varsayılan ``True`` günlük senkronun davranışını korur (her CVE kendi işleminde).
    """
    cve = await session.get(CVE, data.cve_id)
    if cve is None:
        cve = CVE(cve_id=data.cve_id)
        session.add(cve)
    cve.description = data.description
    cve.cvss_score = data.cvss_score
    cve.severity = data.severity
    cve.references = data.references
    cve.category = primary_category(data.description)  # Zafiyet DB kategori çipleri için
    if commit:
        await session.commit()
    if data.cpe_matches:
        await store_cpe_matches(session, data.cve_id, data.cpe_matches, commit=commit)
    return cve


def service_keyword(service: Service) -> str | None:
    """Servisten NVD arama anahtarı üretir (ürün adı + sürüm numarası)."""
    if not service.product:
        return None
    product = service.product.split()[0]
    version = ""
    if service.version:
        match = re.search(r"\d+(?:\.\d+)*", service.version)
        if match:
            version = match.group(0)
    keyword = f"{product} {version}".strip()
    return keyword or None


def _clean_version(raw: str | None) -> str:
    """nmap banner'ından saf sürüm numarasını çıkarır ('2.4.49 (Ubuntu)' → '2.4.49').

    Banner sık sık ek metin (dağıtım, derleme) taşır; ham dize sürüm karşılaştırmasını bozar.
    Numaraya BİTİŞİK tek harf soneki korunur ('1.0.1f' → '1.0.1f') çünkü OpenSSL/Apache tipi
    yamalarda harf-sonek sürümün PARÇASIdır; atılırsa CPE tam-sürüm ('1.0.1f') eşleşmesi kaçar.
    Numaradan boşlukla ayrılmış metin ('2.4.49 (Ubuntu)') yine dışarıda kalır.
    """
    if not raw:
        return ""
    m = re.search(r"\d+(?:\.\d+)*[a-zA-Z]?", raw)
    return m.group(0) if m else ""


def _cve_applies_to_service(data: CveData, version: str) -> bool:
    """CVE'nin CPE konfigürasyonu servisin sürümüne UYGULANIYOR mu? (yanlış-pozitif filtresi).

    NVD keyword araması açıklama metninde GEVŞEK eşleştiği için sürümü etkilemeyen (başka
    sürüm/başka ürün) CVE'leri de döndürür. En az bir 'vulnerable' CPE ölçütü servisin sürümüne
    uymuyorsa (ya da CVE'nin hiç CPE ölçütü yoksa) bulgu üretilmez — offline yolun (CPE-filtreli)
    titizliğini canlı NVD yoluna da taşır. Sürüm bilinmiyorsa ölçüt zaten muhafazakâr eşleşir.
    """
    return any(m.vulnerable and cpe_match_applies(version, m) for m in data.cpe_matches)


async def match_service_cves(session: AsyncSession, scan_id: int, service: Service) -> list[str]:
    """Servisi NVD'de arar, CVE'leri kaydeder, Finding üretir; eşleşen cve_id'leri döndürür.

    Yalnız servisin sürümüne CPE olarak UYGULANAN CVE'ler bulguya çevrilir (keyword aramasının
    döndürdüğü ilgisiz/başka-sürüm CVE gürültüsü süzülür).
    """
    keyword = service_keyword(service)
    if keyword is None:
        return []
    cves = await fetch_cves(keyword)
    version = _clean_version(service.version)
    matched: list[str] = []
    for data in cves:
        if not _cve_applies_to_service(data, version):
            continue  # sürüm/ürün uyumsuz → yanlış-pozitif, bulgu üretme
        await upsert_cve(session, data)
        await create_finding(
            session,
            scan_id,
            title=f"{data.cve_id} — {service.product}",
            severity=data.severity or Severity.info,
            asset_id=service.asset_id,
            service_id=service.id,
            cve_id=data.cve_id,
            risk_score=data.cvss_score,
            description=data.description,
        )
        matched.append(data.cve_id)
    return matched


async def enrich_cves(session: AsyncSession, cve_ids: list[str]) -> None:
    """CVE'leri CISA KEV (aktif sömürü) ve EPSS (olasılık) ile zenginleştirir."""
    if not cve_ids:
        return
    kev = await fetch_kev_set()
    epss = await fetch_epss(cve_ids)
    for cve_id in cve_ids:
        cve = await session.get(CVE, cve_id)
        if cve is None:
            continue
        if cve_id in kev:
            cve.kev_flag = True
        if cve_id in epss:
            cve.epss_score = epss[cve_id]
    await session.commit()


async def apply_risk_scores(session: AsyncSession, cve_ids: list[str]) -> None:
    """Birleşik risk skorunu (CVSS+EPSS+KEV+exploit) Finding VE Vulnerability'ye uygular.

    Exploit sinyali (Exploit-DB/Metasploit) artık skora girer (VI-1). Vulnerability
    satırları da güncellenir → günlük EPSS tazelemesi zafiyet sayfasındaki sıralamayı
    tazeler (yalnız Finding güncellense vuln tablosu eski kalırdı).
    """
    if not cve_ids:
        return
    hits = await exploit_summary_for_cves(session, cve_ids)
    for cve_id in cve_ids:
        cve = await session.get(CVE, cve_id)
        if cve is None:
            continue
        hit = hits.get(cve_id)
        level = exploit_level_from_hit(hit.count, hit.metasploit) if hit else 0
        priority = compute_priority(
            cve.cvss_score,
            cve.epss_score,
            cve.kev_flag,
            exploit_level=level,
            severity=cve.severity.value if cve.severity else None,
        )
        findings = await session.execute(select(Finding).where(Finding.cve_id == cve_id))
        for finding in findings.scalars().all():
            finding.risk_score = priority
        vulns = await session.execute(select(Vulnerability).where(Vulnerability.cve_id == cve_id))
        for vuln in vulns.scalars().all():
            vuln.risk_score = priority
    await session.commit()


async def cves_by_ids(session: AsyncSession, cve_ids: list[str]) -> dict[str, CVE]:
    if not cve_ids:
        return {}
    result = await session.execute(select(CVE).where(CVE.cve_id.in_(cve_ids)))
    return {cve.cve_id: cve for cve in result.scalars().all()}
