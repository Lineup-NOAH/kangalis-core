"""NVD (National Vulnerability Database) API 2.0 entegrasyonu.

`fetch_cves` ağ çağrısı yapar (hata/timeout'ta boş liste döner); `parse_nvd_response`
saf ayrıştırma (birim testi edilebilir).
"""

from __future__ import annotations

import asyncio
import math
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from cybersectool.config import settings
from cybersectool.core.exploits import ExploitRecord
from cybersectool.core.models import ExploitSource, Severity
from cybersectool.intel.cpe import CpeMatchData, extract_cpe_matches

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NVD API tek istekte en çok 120 günlük (pubStartDate–pubEndDate) aralık kabul eder.
NVD_MAX_WINDOW_DAYS = 120
# Her 120 günlük pencere için varsayılan sayfa (istek) bütçesi — 2000 sonuç/sayfa ×8 = 16k CVE.
NVD_PAGES_PER_WINDOW = 8

_SEVERITY_MAP = {
    "CRITICAL": Severity.critical,
    "HIGH": Severity.high,
    "MEDIUM": Severity.medium,
    "LOW": Severity.low,
}


@dataclass
class CveData:
    cve_id: str
    description: str | None = None
    cvss_score: float | None = None
    severity: Severity | None = None
    references: list[str] = field(default_factory=list)
    cpe_matches: list[CpeMatchData] = field(default_factory=list)


def _extract_cvss(metrics: dict[str, Any]) -> tuple[float | None, Severity | None]:
    """CVSS taban skoru + önemini çıkarır. v4.0 > v3.1 > v3.0 > v2 önceliği (#136).

    2024'ten itibaren NVD yeni CVE'lerde yalnız CVSS v4.0 yayımlayabiliyor; v4 atlanırsa o
    CVE skorsuz/severitysiz kalırdı. Her metrik içinde NVD (``type == "Primary"``) sağlayıcı
    yeğlenir; yoksa ilk girdi (bazı CVE'lerde Secondary/CNA skoru ilk gelebilir).
    """
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if not entries:
            continue
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        cvss = entry.get("cvssData", {})
        score = cvss.get("baseScore")
        sev_str = cvss.get("baseSeverity") or entry.get("baseSeverity")
        severity = _SEVERITY_MAP.get(str(sev_str).upper()) if sev_str else None
        return (float(score) if score is not None else None, severity)
    return (None, None)


def parse_nvd_response(data: dict[str, Any]) -> list[CveData]:
    results: list[CveData] = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        # Reddedilmiş CVE'leri atla (#137): NVD bunları "Rejected" işaretler (geçersiz/geri
        # çekilmiş zafiyet). Yerel depoya yazılırsa eşleşip sahte bulgu üretirdi.
        if str(cve.get("vulnStatus") or "").strip().lower() == "rejected":
            continue
        description = None
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value")
                break
        score, severity = _extract_cvss(cve.get("metrics", {}))
        refs = [r.get("url") for r in cve.get("references", []) if r.get("url")]
        results.append(
            CveData(
                cve_id=str(cve_id),
                description=description,
                cvss_score=score,
                severity=severity,
                references=refs[:10],
                cpe_matches=extract_cpe_matches(cve),
            )
        )
    return results


def parse_rejected_cve_ids(data: dict[str, Any]) -> list[str]:
    """NVD yanıtındaki 'Rejected' statülü CVE id'lerini döndürür (geç-reddedilenleri SİLMEK için).

    Bir CVE yayımlandıktan SONRA NVD'de Rejected'a düşebilir (geçersiz/geri çekilmiş). lastMod
    penceresinde bu durumla döner; ``parse_nvd_response`` bunları sonuç listesine ALMAZ → ayrıca
    toplanıp yerel depodan silinmezlerse eşleşmeye devam edip sahte bulgu üretirler.
    """
    out: list[str] = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cid = cve.get("id")
        if cid and str(cve.get("vulnStatus") or "").strip().lower() == "rejected":
            out.append(str(cid))
    return out


async def fetch_cves(keyword: str, limit: int = 10) -> list[CveData]:
    """NVD'de anahtar kelimeye göre CVE arar. Hata/timeout'ta boş liste döner."""
    params = {"keywordSearch": keyword, "resultsPerPage": str(limit)}
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(NVD_URL, params=params)
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, ValueError):
        return []
    return parse_nvd_response(data)


# --- Yerel zafiyet/exploit deposu için toplu CVE içe aktarma ---


def nvd_response_to_records(data: dict[str, Any]) -> list[ExploitRecord]:
    """NVD yanıtını exploit deposu için ExploitRecord listesine çevirir (kaynak=nvd)."""
    records: list[ExploitRecord] = []
    for cve in parse_nvd_response(data):
        records.append(
            ExploitRecord(
                source=ExploitSource.nvd,
                external_id=cve.cve_id,
                title=cve.description or cve.cve_id,
                type=(cve.severity.value if cve.severity else None),  # önem (severity)
                date=None,
                rank=(str(cve.cvss_score) if cve.cvss_score is not None else None),  # CVSS
                cve_ids=[cve.cve_id],
                url=f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}",
            )
        )
    return records


def _resolve_api_key(api_key: str | None) -> str:
    """Etkin NVD API anahtarı: açıkça verilen (DB) → yoksa ortam değişkeni (config) fallback."""
    return (api_key or settings.nvd_api_key or "").strip()


def _headers(api_key: str | None = None) -> dict[str, str]:
    key = _resolve_api_key(api_key)
    return {"apiKey": key} if key else {}


def _request_delay(api_key: str | None = None) -> float:
    """İstekler arası bekleme (sn). NVD anahtarı varsa 50 istek/30sn, yoksa 5/30sn sınırı."""
    return 0.6 if _resolve_api_key(api_key) else 6.0


def _date_windows(
    start: datetime, end: datetime, span_days: int = NVD_MAX_WINDOW_DAYS
) -> list[tuple[datetime, datetime]]:
    """``[start, end]`` aralığını ``span_days`` günü aşmayan ardışık pencerelere böler.

    NVD API tek istekte en çok 120 günlük aralık kabul ettiği için, daha geniş kapsam
    pencerelere bölünerek toplanır. ``start >= end`` ise tek pencere döner.
    """
    windows: list[tuple[datetime, datetime]] = []
    span = timedelta(days=span_days)
    cur = start
    while cur < end:
        nxt = min(cur + span, end)
        windows.append((cur, nxt))
        cur = nxt
    return windows or [(start, end)]


def _default_max_pages(days: int) -> int:
    """Yapılandırılan pencereyi kapsamaya yetecek varsayılan toplam sayfa bütçesi."""
    windows = max(1, math.ceil(max(days, 1) / NVD_MAX_WINDOW_DAYS))
    return windows * NVD_PAGES_PER_WINDOW


async def _fetch_nvd_pages(
    days: int, max_pages: int, *, api_key: str | None = None, last_mod: bool = False
) -> list[dict[str, Any]]:
    """Son `days` günün NVD CVE sayfalarını (ham JSON) çeker.

    `days` > 120 ise aralık, NVD'nin 120-gün/istek sınırına uyacak şekilde ardışık
    pencerelere bölünür; her pencere kendi içinde sayfalanır (startIndex). `max_pages`
    tüm pencereler genelinde TOPLAM istek bütçesidir (anahtarsız rate-limit'i korur).
    `api_key` verilirse rate-limit hızlanır + apiKey header'ı gönderilir (yoksa config fallback).

    `last_mod=True` ise YAYIM yerine SON DEĞİŞİKLİK tarihine (lastModStartDate/Date) göre
    çeker → CVSS/CPE/red durumu sonradan güncellenen CVE'leri tazelemek için (#144).
    """
    end = datetime.now(UTC)
    start = end - timedelta(days=max(days, 1))
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    start_key, end_key = (
        ("lastModStartDate", "lastModEndDate") if last_mod else ("pubStartDate", "pubEndDate")
    )
    delay = _request_delay(api_key)
    headers = _headers(api_key)
    pages: list[dict[str, Any]] = []
    requests_made = 0
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            for win_start, win_end in _date_windows(start, end):
                start_index = 0
                while requests_made < max_pages:
                    if requests_made > 0:
                        await asyncio.sleep(delay)  # rate-limit'e saygı (pencereler arası dahil)
                    params = {
                        start_key: win_start.strftime(fmt),
                        end_key: win_end.strftime(fmt),
                        "resultsPerPage": "2000",
                        "startIndex": str(start_index),
                    }
                    resp = await client.get(NVD_URL, params=params, headers=headers)
                    resp.raise_for_status()
                    data = resp.json()
                    pages.append(data)
                    requests_made += 1
                    vulns = data.get("vulnerabilities", [])
                    total = int(data.get("totalResults", 0))
                    start_index += len(vulns)
                    if not vulns or start_index >= total:
                        break  # bu pencere bitti → sonraki pencereye geç
                if requests_made >= max_pages:
                    break  # toplam bütçe doldu
    except (httpx.HTTPError, ValueError):
        return pages
    return pages


async def fetch_nvd_recent(
    days: int | None = None, max_pages: int | None = None, *, api_key: str | None = None
) -> list[ExploitRecord]:
    """Son `days` günde yayımlanan CVE'leri exploit deposu için toplu çeker (pencereli, sayfalı).

    `days` verilmezse `settings.nvd_sync_days` kullanılır; `max_pages` verilmezse pencere
    sayısına göre türetilir. `api_key` verilmezse config fallback (DB'deki anahtar buradan geçer).
    """
    days = settings.nvd_sync_days if days is None else days
    max_pages = _default_max_pages(days) if max_pages is None else max_pages
    records: list[ExploitRecord] = []
    for page in await _fetch_nvd_pages(days, max_pages, api_key=api_key):
        records.extend(nvd_response_to_records(page))
    return records


async def fetch_nvd_cve_data(
    days: int | None = None,
    max_pages: int | None = None,
    *,
    api_key: str | None = None,
    last_mod: bool = False,
) -> list[CveData]:
    """Son `days` günde yayımlanan CVE'leri CPE konfigürasyonlarıyla çeker (offline eşleştirme).

    `days` verilmezse `settings.nvd_sync_days`, `max_pages` verilmezse pencere sayısına
    göre türetilir — böylece CPE indeksi exploit senkronuyla aynı pencereyi kapsar.
    `api_key` verilmezse config fallback (DB'deki anahtar buradan geçer). `last_mod=True` ise
    yayım yerine SON DEĞİŞİKLİK tarihine göre çeker (güncellenen CVE'leri tazeleme — #144).
    """
    days = settings.nvd_sync_days if days is None else days
    max_pages = _default_max_pages(days) if max_pages is None else max_pages
    cves: list[CveData] = []
    for page in await _fetch_nvd_pages(days, max_pages, api_key=api_key, last_mod=last_mod):
        cves.extend(parse_nvd_response(page))
    return cves


async def fetch_nvd_modified(
    days: int | None = None, max_pages: int | None = None, *, api_key: str | None = None
) -> tuple[list[CveData], list[str]]:
    """SON DEĞİŞİKLİK (lastMod) penceresini TEK çekişte hem güncel veri hem REDDEDİLEN id'leri
    olarak döndürür: ``(cves, rejected_ids)``.

    Aynı sayfalar iki kez indirilmesin diye birleşik: ``cves`` tazeleme için (rejected hariç,
    ``parse_nvd_response``), ``rejected_ids`` ise yerelden SİLME için (``parse_rejected_cve_ids``).
    Geç-reddedilen CVE'lerin temizlenmesini sağlar (#144 tazeleme + sahte-bulgu önleme).
    """
    days = settings.nvd_sync_days if days is None else days
    max_pages = _default_max_pages(days) if max_pages is None else max_pages
    cves: list[CveData] = []
    rejected: list[str] = []
    for page in await _fetch_nvd_pages(days, max_pages, api_key=api_key, last_mod=True):
        cves.extend(parse_nvd_response(page))
        rejected.extend(parse_rejected_cve_ids(page))
    return cves, rejected
