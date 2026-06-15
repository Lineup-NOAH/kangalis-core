"""Offline CPE eşleştirme testleri (saf ayrıştırma + DB eşleştirme)."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.assets import upsert_asset, upsert_service
from cybersectool.core.cpe import (
    count_cpe_matches,
    find_matching_cves,
    match_service_cves_offline,
    store_cpe_matches,
)
from cybersectool.core.findings import count_open_findings
from cybersectool.core.models import CVE, ScanType, Severity
from cybersectool.core.scans import create_scan
from cybersectool.intel.cpe import (
    CpeMatchData,
    alias_candidates,
    compare_versions,
    cpe_match_applies,
    extract_cpe_matches,
    parse_cpe,
)
from cybersectool.intel.nvd import parse_nvd_response

# --- saf ayrıştırma ---


def test_parse_cpe_23() -> None:
    p = parse_cpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
    assert p is not None
    assert (p.part, p.vendor, p.product, p.version) == ("a", "apache", "http_server", "2.4.49")


def test_parse_cpe_22_uri() -> None:
    p = parse_cpe("cpe:/a:apache:http_server:2.4.49")
    assert p is not None
    assert (p.vendor, p.product, p.version) == ("apache", "http_server", "2.4.49")


def test_parse_cpe_invalid() -> None:
    assert parse_cpe(None) is None
    assert parse_cpe("not-a-cpe") is None


def test_compare_versions() -> None:
    assert compare_versions("2.4.49", "2.4.51") == -1
    assert compare_versions("2.4.51", "2.4.49") == 1
    assert compare_versions("2.4", "2.4.0") == 0
    assert compare_versions("1.0.0", "1.0.0") == 0
    assert compare_versions("2.4", "2.4.0.0") == 0  # tüm eksik son parçalar sıfır → eşit


def test_compare_versions_letter_suffix() -> None:
    """DÜŞÜK fix: harf-sonek SONRAKİ yamadır (OpenSSL/Apache); eksik parça harften küçük.

    Eskiden eksik parça (1,0,"") harf token'ından (0,0,s) büyük sayılıyor → taban sürüm
    ``1.0.1``, ``1.0.1g``'den BÜYÜK çıkıp Heartbleed aralığını (endExcluding=1.0.1g) KAÇIRIYORDU.
    """
    assert compare_versions("2.4.49a", "2.4.49") == 1  # harf-sonek = sonraki yama → büyük
    assert compare_versions("2.4.49", "2.4.49a") == -1
    assert compare_versions("1.0.1", "1.0.1g") == -1  # taban sürüm harf-yamadan KÜÇÜK (kritik)
    assert compare_versions("1.0.1g", "1.0.1") == 1
    assert compare_versions("1.0.1f", "1.0.1g") == -1  # f < g
    assert compare_versions("1.0.1a", "1.0.1a") == 0


def _match(**kw: object) -> object:
    from cybersectool.intel.cpe import CpeMatchData

    base = {"criteria": "x", "part": "a", "vendor": "v", "product": "p", "version": "*"}
    base.update(kw)
    return CpeMatchData(**base)  # type: ignore[arg-type]


def test_cpe_match_applies_range() -> None:
    m = _match(version_start_including="2.4.0", version_end_excluding="2.4.51")
    assert cpe_match_applies("2.4.49", m) is True  # type: ignore[arg-type]
    assert cpe_match_applies("2.4.51", m) is False  # type: ignore[arg-type]
    assert cpe_match_applies("2.3.0", m) is False  # type: ignore[arg-type]


def test_cpe_match_applies_exact() -> None:
    m = _match(version="2.4.49")
    assert cpe_match_applies("2.4.49", m) is True  # type: ignore[arg-type]
    assert cpe_match_applies("2.4.50", m) is False  # type: ignore[arg-type]


def test_cpe_match_applies_wildcard_no_bounds() -> None:
    m = _match(version="*")
    # sürümsüz ölçüt + sınır yok → ürünün her sürümü
    assert cpe_match_applies("9.9.9", m) is True  # type: ignore[arg-type]
    assert cpe_match_applies(None, m) is True  # type: ignore[arg-type]


def test_cpe_match_applies_letter_bound_base_version() -> None:
    """DÜŞÜK fix: harf-sınırlı aralıkta TABAN sürüm de kapsanır (Heartbleed: <1.0.1g).

    OpenSSL 1.0.1..1.0.1f zafiyetli, 1.0.1g'de yamalı (versionEndExcluding=1.0.1g). Eskiden taban
    sürüm ``1.0.1`` yanlışlıkla ``1.0.1g``'den BÜYÜK sayılıp aralık dışında kalıyordu (yanlış-neg.).
    """
    m = _match(version="*", version_start_including="1.0.1", version_end_excluding="1.0.1g")
    assert cpe_match_applies("1.0.1", m) is True  # taban sürüm → ZAFİYETLİ (eskiden kaçıyordu)
    assert cpe_match_applies("1.0.1f", m) is True  # f < g → zafiyetli
    assert cpe_match_applies("1.0.1g", m) is False  # yamalı sürüm → kapsam dışı


SAMPLE_WITH_CONFIG = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-41773",
                "descriptions": [{"lang": "en", "value": "Apache path traversal"}],
                "metrics": {
                    "cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]
                },
                "configurations": [
                    {
                        "nodes": [
                            {
                                "operator": "OR",
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                                        "versionStartIncluding": "2.4.49",
                                        "versionEndIncluding": "2.4.49",
                                    }
                                ],
                            }
                        ]
                    }
                ],
            }
        }
    ]
}


def test_extract_cpe_matches() -> None:
    cve = SAMPLE_WITH_CONFIG["vulnerabilities"][0]["cve"]
    matches = extract_cpe_matches(cve)
    assert len(matches) == 1
    assert matches[0].vendor == "apache"
    assert matches[0].product == "http_server"
    assert matches[0].version_start_including == "2.4.49"


def test_parse_nvd_response_carries_cpe() -> None:
    cves = parse_nvd_response(SAMPLE_WITH_CONFIG)
    assert len(cves) == 1
    assert len(cves[0].cpe_matches) == 1
    assert cves[0].cpe_matches[0].product == "http_server"


# --- vendor/ürün alias (COV-4b, saf) ---


def test_alias_candidates_vendor_alias() -> None:
    """CPE vendor 'redis' olsa bile alias 'redislabs' adayını da üretir (kaçak kapanır)."""
    cands = alias_candidates("redis", "redis", "Redis key-value store", "redis")
    assert cands[0] == ("redis", "redis")  # CPE'den gelen birebir önce
    assert ("redislabs", "redis") in cands


def test_alias_candidates_no_cpe_from_banner() -> None:
    """CPE yokken banner ürün/servis adından aday türetir (OpenSSH→openbsd)."""
    cands = alias_candidates(None, None, "OpenSSH", "ssh")
    assert ("openbsd", "openssh") in cands


def test_alias_candidates_generic_token_no_match() -> None:
    """Genel 'httpd'/'server' tek başına ürün ayırt etmez → aday üretmez (FP yok)."""
    assert alias_candidates(None, None, "Some httpd server", None) == []


def test_alias_candidates_unknown_returns_empty() -> None:
    assert alias_candidates(None, None, "totally-unknown-thing", None) == []


# --- DB katmanı ---


async def test_offline_matching_end_to_end(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    cves = parse_nvd_response(SAMPLE_WITH_CONFIG)
    async with session_factory() as session:
        # CVE + CPE ölçütlerini yerelde sakla
        cve = CVE(
            cve_id="CVE-2021-41773",
            description="Apache path traversal",
            cvss_score=7.5,
            severity=Severity.high,
        )
        session.add(cve)
        await session.commit()
        written = await store_cpe_matches(session, "CVE-2021-41773", cves[0].cpe_matches)
        assert written == 1
        assert await count_cpe_matches(session) == 1

        # Eşleşen sürüm
        hit = await find_matching_cves(session, "apache", "http_server", "2.4.49")
        assert hit == ["CVE-2021-41773"]
        # Aralık dışı sürüm
        miss = await find_matching_cves(session, "apache", "http_server", "2.4.48")
        assert miss == []

        # Servis → offline eşleştirme → Finding
        asset = await upsert_asset(session, "10.0.0.20")
        service = await upsert_service(
            session,
            asset.id,
            443,
            product="Apache httpd",
            version="2.4.49",
            cpe="cpe:/a:apache:http_server:2.4.49",
        )
        scan = await create_scan(session, ScanType.network, "10.0.0.20")
        matched = await match_service_cves_offline(session, scan.id, service)
        assert matched == ["CVE-2021-41773"]
        assert await count_open_findings(session) == 1


async def test_offline_matching_no_cpe_returns_empty(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        asset = await upsert_asset(session, "10.0.0.21")
        service = await upsert_service(session, asset.id, 22, product="OpenSSH", version="8.9")
        scan = await create_scan(session, ScanType.network, "10.0.0.21")
        # CPE yok + yerelde eşleşen CPE kaydı yok → boş döner (graceful, FP üretmez).
        assert await match_service_cves_offline(session, scan.id, service) == []


async def test_offline_matching_vendor_alias(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """CPE vendor 'redis' ama yerel kayıt 'redislabs' → alias eşleşmeyi yakalar (COV-4b)."""
    async with session_factory() as session:
        session.add(CVE(cve_id="CVE-2099-0001", description="Redis flaw", severity=Severity.high))
        await session.commit()
        # NVD kaydı vendor 'redislabs' altında — nmap ise 'redis' der.
        match = CpeMatchData(
            criteria="cpe:2.3:a:redislabs:redis:5.0.0:*:*:*:*:*:*:*",
            part="a",
            vendor="redislabs",
            product="redis",
            version="5.0.0",
        )
        await store_cpe_matches(session, "CVE-2099-0001", [match])

        asset = await upsert_asset(session, "10.0.0.30")
        service = await upsert_service(
            session,
            asset.id,
            6379,
            product="Redis key-value store",
            version="5.0.0",
            cpe="cpe:/a:redis:redis:5.0.0",  # vendor 'redis' → tam-eşleşme KAÇIRIRDI
        )
        scan = await create_scan(session, ScanType.network, "10.0.0.30")
        matched = await match_service_cves_offline(session, scan.id, service)
        assert matched == ["CVE-2099-0001"]
        assert await count_open_findings(session) == 1


async def test_offline_matching_no_cpe_alias_fallback(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """CPE hiç yokken banner (OpenSSH→openbsd) ile yerel CVE'yi yakalar (COV-4b fallback)."""
    async with session_factory() as session:
        session.add(CVE(cve_id="CVE-2099-0002", description="SSH flaw", severity=Severity.medium))
        await session.commit()
        match = CpeMatchData(
            criteria="cpe:2.3:a:openbsd:openssh:8.9:*:*:*:*:*:*:*",
            part="a",
            vendor="openbsd",
            product="openssh",
            version="8.9",
        )
        await store_cpe_matches(session, "CVE-2099-0002", [match])

        asset = await upsert_asset(session, "10.0.0.31")
        # CPE alanı YOK → fallback banner ürün adından aday türetmeli.
        service = await upsert_service(session, asset.id, 22, product="OpenSSH", version="8.9")
        scan = await create_scan(session, ScanType.network, "10.0.0.31")
        matched = await match_service_cves_offline(session, scan.id, service)
        assert matched == ["CVE-2099-0002"]
        assert await count_open_findings(session) == 1


async def test_store_cpe_matches_idempotent(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    cves = parse_nvd_response(SAMPLE_WITH_CONFIG)
    async with session_factory() as session:
        await store_cpe_matches(session, "CVE-2021-41773", cves[0].cpe_matches)
        await store_cpe_matches(session, "CVE-2021-41773", cves[0].cpe_matches)
        # Tekrar yazım eskiyi siler → tek satır kalır
        assert await count_cpe_matches(session) == 1


async def test_create_finding_idempotent(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Aynı (scan, asset, service, cve, title) bulgu TEK yazılır (offline+online çift-yazım fix).

    Eskiden yerel CPE bankası + canlı NVD aynı CVE'yi 2 kez finding yazıyordu → raporda kopya.
    Farklı başlık (ör. EXPLOITED) AYRI kalır; validated bayrağı en iyiye yükseltilir.
    """
    from cybersectool.core.findings import create_finding, list_findings_by_risk

    async with session_factory() as session:
        asset = await upsert_asset(session, "10.0.0.30")
        service = await upsert_service(session, asset.id, 80, product="Apache", version="2.4.49")
        scan = await create_scan(session, ScanType.network, "10.0.0.30")
        kw = {"asset_id": asset.id, "service_id": service.id, "cve_id": "CVE-2021-42013"}
        # Aynı bulgu iki kez (offline + online eşleştirici simülasyonu) → tek satır kalmalı.
        f1 = await create_finding(session, scan.id, "CVE-2021-42013 — Apache httpd", **kw)
        f2 = await create_finding(session, scan.id, "CVE-2021-42013 — Apache httpd", **kw)
        assert f1.id == f2.id  # ikinci çağrı mevcut bulguyu döndürdü (yeni yazmadı)
        # Farklı başlık (EXPLOITED) AYRI bulgu olmalı.
        await create_finding(session, scan.id, "EXPLOITED: CVE-2021-42013 → kod", **kw)
        findings = await list_findings_by_risk(session, scan_id=scan.id)
        titles = sorted(f.title for f in findings)
        assert titles == ["CVE-2021-42013 — Apache httpd", "EXPLOITED: CVE-2021-42013 → kod"]
        # validated yükseltme: doğrulanmamış bulgu sonradan doğrulanmış çağrıyla True olur.
        assert f1.validated is False
        f3 = await create_finding(
            session, scan.id, "CVE-2021-42013 — Apache httpd", validated=True, **kw
        )
        assert f3.id == f1.id and f3.validated is True


def test_parse_rejected_cve_ids() -> None:
    """ORTA fix: geç-reddedilen CVE id'leri toplanır (parse_nvd_response onları sonuca ALMAZ)."""
    from cybersectool.intel.nvd import parse_rejected_cve_ids

    data = {
        "vulnerabilities": [
            {"cve": {"id": "CVE-2021-1", "vulnStatus": "Analyzed"}},
            {"cve": {"id": "CVE-2021-2", "vulnStatus": "Rejected"}},
            {"cve": {"id": "CVE-2021-3", "vulnStatus": "REJECTED"}},  # büyük-küçük harf duyarsız
        ]
    }
    assert parse_rejected_cve_ids(data) == ["CVE-2021-2", "CVE-2021-3"]
    assert [c.cve_id for c in parse_nvd_response(data)] == ["CVE-2021-1"]  # red sonuca girmez


async def test_delete_cves_removes_cve_and_matches(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """ORTA fix: delete_cves CVE + CPE eşleşmelerini siler (geç-red temizliği → sahte bulgu yok)."""
    from cybersectool.core.cpe import delete_cves
    from cybersectool.intel.cpe import CpeMatchData

    async with session_factory() as session:
        session.add(CVE(cve_id="CVE-2099-9999", description="x", severity=Severity.high))
        await session.commit()
        await store_cpe_matches(
            session,
            "CVE-2099-9999",
            [CpeMatchData(criteria="c", part="a", vendor="v", product="p", version="*")],
        )
        assert await count_cpe_matches(session) == 1
        removed = await delete_cves(session, ["CVE-2099-9999"])
        assert removed == 1
        assert await count_cpe_matches(session) == 0
        assert await session.get(CVE, "CVE-2099-9999") is None
        assert await delete_cves(session, []) == 0  # boş liste → no-op
