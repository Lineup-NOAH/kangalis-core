"""Zafiyet yaşam döngüsü testleri (sertleştirilmiş motor).

Kapsanan davranış: dedup, kapsam-bilinçli oto-çözüm (erişilen host + coverage guard +
domain izolasyonu + elle-port koruması), reopen, manuel triyaj korunması ve sorgular.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.assets import upsert_asset
from cybersectool.core.findings import create_finding
from cybersectool.core.models import (
    Asset,
    FindingStatus,
    Scan,
    ScanType,
    Severity,
    Vulnerability,
)
from cybersectool.core.scans import create_scan
from cybersectool.core.vulnerabilities import (
    count_vulnerabilities,
    finding_fingerprint,
    get_vulnerability,
    list_vulnerabilities,
    set_vuln_status,
    severity_counts_open,
    sync_vulnerabilities_for_scan,
    vuln_lifecycle_stats,
    vuln_trend,
)

# Sabit zaman çapaları: T1, T0'dan 1 saat sonra (erişim sinyali kontrolü için).
T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
T1 = T0 + timedelta(hours=1)


async def _set_scan_window(
    session: AsyncSession,
    scan: Scan,
    *,
    started_at: datetime | None = None,
    ports: str | None = None,
    target: str | None = None,
) -> None:
    """Tarama kapsam/zamanlama alanlarını (started_at, ports, target) ayarlar."""
    scan.started_at = started_at
    scan.ports = ports
    if target is not None:
        scan.target = target
    await session.commit()


async def _set_asset_last_seen(session: AsyncSession, asset: Asset, when: datetime) -> None:
    """Bir varlığın last_seen alanını ayarlar (tarayıcının up-host bump'ını taklit eder)."""
    asset.last_seen = when
    await session.commit()


# 1 -------------------------------------------------------------------------
async def test_dedup_no_duplicates_on_resync(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """2 bulgu → 2 vuln; aynı taramayı tekrar sync → hâlâ 2 vuln (aynı id'ler)."""
    async with session_factory() as session:
        asset = await upsert_asset(session, "10.0.0.5")
        scan = await create_scan(session, ScanType.network, "10.0.0.5")
        await create_finding(
            session, scan.id, "A", severity=Severity.high, asset_id=asset.id, cve_id="CVE-A"
        )
        await create_finding(
            session, scan.id, "B", severity=Severity.medium, asset_id=asset.id, cve_id="CVE-B"
        )
        res1 = await sync_vulnerabilities_for_scan(session, scan.id)
        assert res1["upserted"] == 2
        assert await count_vulnerabilities(session) == 2
        first = await list_vulnerabilities(session)
        ids_before = {v.id for v in first}
        # last_seen dolu (tz-aware round-trip karşılaştırması KIRILGAN olduğu için yapılmaz).
        assert all(v.last_seen is not None for v in first)

        # Aynı bulgularla ikinci sync → yeni satır yok, aynı id'ler, kopya yok.
        res2 = await sync_vulnerabilities_for_scan(session, scan.id)
        assert res2["upserted"] == 2
        assert res2["reopened"] == 0
        assert await count_vulnerabilities(session) == 2
        again = await list_vulnerabilities(session)
        assert {v.id for v in again} == ids_before
        assert all(v.last_seen is not None for v in again)


# 2 -------------------------------------------------------------------------
async def test_auto_resolve_reached_host_full_coverage(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Erişilen host + top kapsam: bulgu kaybolunca vuln oto-çözülür."""
    async with session_factory() as session:
        asset = await upsert_asset(session, "10.0.0.5")
        scan1 = await create_scan(session, ScanType.network, "10.0.0.5")
        await _set_scan_window(session, scan1, started_at=T0, ports=None, target="10.0.0.5")
        await _set_asset_last_seen(session, asset, T0)  # T0'da erişilen host
        await create_finding(
            session, scan1.id, "A", severity=Severity.high, asset_id=asset.id, cve_id="CVE-A"
        )
        await sync_vulnerabilities_for_scan(session, scan1.id)
        vulns = await list_vulnerabilities(session)
        assert len(vulns) == 1
        assert vulns[0].status == FindingStatus.open

        # scan2: aynı IP, top kapsam, T1'de erişilir ama bulgu YOK → oto-çözüm.
        scan2 = await create_scan(session, ScanType.network, "10.0.0.5")
        await _set_scan_window(session, scan2, started_at=T1, ports=None, target="10.0.0.5")
        await _set_asset_last_seen(session, asset, T1)
        res = await sync_vulnerabilities_for_scan(session, scan2.id)
        assert res["resolved"] >= 1
        v = (await list_vulnerabilities(session, resolved=True))[0]
        assert v.status == FindingStatus.resolved
        assert v.resolved_at is not None


# 3 -------------------------------------------------------------------------
async def test_offline_host_not_resolved(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """C1: /24 taramasında erişilmeyen (kapalı) host'un vuln'ü açık kalır."""
    async with session_factory() as session:
        asset = await upsert_asset(session, "10.0.0.5")
        scan1 = await create_scan(session, ScanType.network, "10.0.0.0/24")
        await _set_scan_window(session, scan1, started_at=T0, ports=None, target="10.0.0.0/24")
        await _set_asset_last_seen(session, asset, T0)
        await create_finding(
            session, scan1.id, "A", severity=Severity.high, asset_id=asset.id, cve_id="CVE-A"
        )
        await sync_vulnerabilities_for_scan(session, scan1.id)

        # scan2: /24, T1'de başlar ama host last_seen=T0 (< T1) → kapalı, bulgu yok.
        scan2 = await create_scan(session, ScanType.network, "10.0.0.0/24")
        await _set_scan_window(session, scan2, started_at=T1, ports=None, target="10.0.0.0/24")
        # asset.last_seen T0'da kalır (offline) → erişilmiş sayılmaz.
        res = await sync_vulnerabilities_for_scan(session, scan2.id)
        assert res["resolved"] == 0
        v = (await list_vulnerabilities(session))[0]
        assert v.status == FindingStatus.open


# 4 -------------------------------------------------------------------------
async def test_custom_port_scan_resolves_nothing(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Elle-port taraması (rank 0) host erişilse bile HİÇBİR şeyi çözmez."""
    async with session_factory() as session:
        asset = await upsert_asset(session, "10.0.0.5")
        scan1 = await create_scan(session, ScanType.network, "10.0.0.5")
        await _set_scan_window(session, scan1, started_at=T0, ports=None, target="10.0.0.5")
        await _set_asset_last_seen(session, asset, T0)
        await create_finding(
            session, scan1.id, "A", severity=Severity.high, asset_id=asset.id, cve_id="CVE-A"
        )
        await sync_vulnerabilities_for_scan(session, scan1.id)

        # scan2: elle port listesi (rank 0), host T1'de erişilir, bulgu yok → açık kalır.
        scan2 = await create_scan(session, ScanType.network, "10.0.0.5", ports="80,443")
        await _set_scan_window(session, scan2, started_at=T1, ports="80,443", target="10.0.0.5")
        await _set_asset_last_seen(session, asset, T1)
        res = await sync_vulnerabilities_for_scan(session, scan2.id)
        assert res["resolved"] == 0
        v = (await list_vulnerabilities(session))[0]
        assert v.status == FindingStatus.open


# 5 -------------------------------------------------------------------------
async def test_coverage_guard_narrow_scan_cannot_resolve_broad(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """C2: all-ports (rank 2) görülen vuln'ü top (rank 1) çözemez; sonraki all-ports çözer."""
    async with session_factory() as session:
        asset = await upsert_asset(session, "10.0.0.5")
        # scan1: TÜM portlar (rank 2) → vuln.coverage == 2.
        scan1 = await create_scan(session, ScanType.network, "10.0.0.5", ports="all")
        await _set_scan_window(session, scan1, started_at=T0, ports="all", target="10.0.0.5")
        await _set_asset_last_seen(session, asset, T0)
        await create_finding(
            session, scan1.id, "A", severity=Severity.high, asset_id=asset.id, cve_id="CVE-A"
        )
        await sync_vulnerabilities_for_scan(session, scan1.id)
        v0 = (await list_vulnerabilities(session))[0]
        assert v0.coverage == 2

        # scan2: TOP kapsam (rank 1), erişilir, bulgu yok → coverage 2 > 1, çözülmez.
        scan2 = await create_scan(session, ScanType.network, "10.0.0.5")
        await _set_scan_window(session, scan2, started_at=T1, ports=None, target="10.0.0.5")
        await _set_asset_last_seen(session, asset, T1)
        res2 = await sync_vulnerabilities_for_scan(session, scan2.id)
        assert res2["resolved"] == 0
        assert (await list_vulnerabilities(session))[0].status == FindingStatus.open

        # scan3: TÜM portlar (rank 2) tekrar, erişilir, bulgu yok → artık çözülür.
        T2 = T1 + timedelta(hours=1)
        scan3 = await create_scan(session, ScanType.network, "10.0.0.5", ports="all")
        await _set_scan_window(session, scan3, started_at=T2, ports="all", target="10.0.0.5")
        await _set_asset_last_seen(session, asset, T2)
        res3 = await sync_vulnerabilities_for_scan(session, scan3.id)
        assert res3["resolved"] == 1
        assert (await list_vulnerabilities(session, resolved=True))[0].status == (
            FindingStatus.resolved
        )


# 6 -------------------------------------------------------------------------
async def test_domain_isolation_web_scan_does_not_resolve_network(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Web taraması (farklı domain) ağ zafiyetini çözmez — host kapsanmış olsa bile."""
    async with session_factory() as session:
        asset = await upsert_asset(session, "10.0.0.5")
        scan1 = await create_scan(session, ScanType.network, "10.0.0.5")
        await _set_scan_window(session, scan1, started_at=T0, ports=None, target="10.0.0.5")
        await _set_asset_last_seen(session, asset, T0)
        await create_finding(
            session, scan1.id, "A", severity=Severity.high, asset_id=asset.id, cve_id="CVE-A"
        )
        await sync_vulnerabilities_for_scan(session, scan1.id)

        # WEB taraması: aynı varlıkta FARKLI bir web bulgusu (host bulgu ile kapsanır),
        # ağ vuln'ü domain izolasyonu nedeniyle DOKUNULMAZ.
        scan2 = await create_scan(session, ScanType.web, "10.0.0.5")
        await _set_scan_window(session, scan2, started_at=T1, ports=None, target="10.0.0.5")
        await _set_asset_last_seen(session, asset, T1)
        await create_finding(
            session, scan2.id, "XSS", severity=Severity.medium, asset_id=asset.id, cve_id="CVE-W"
        )
        res = await sync_vulnerabilities_for_scan(session, scan2.id)
        assert res["resolved"] == 0
        net_vuln = next(v for v in await list_vulnerabilities(session) if v.cve_id == "CVE-A")
        assert net_vuln.status == FindingStatus.open


# 7 -------------------------------------------------------------------------
async def test_reopen_resolved_vuln_on_redetect(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Çözülmüş vuln yeniden tespit edilince reopened (open, reopened_count+1)."""
    async with session_factory() as session:
        asset = await upsert_asset(session, "10.0.0.5")
        scan1 = await create_scan(session, ScanType.network, "10.0.0.5")
        await _set_scan_window(session, scan1, started_at=T0, ports=None, target="10.0.0.5")
        await _set_asset_last_seen(session, asset, T0)
        await create_finding(
            session, scan1.id, "A", severity=Severity.high, asset_id=asset.id, cve_id="CVE-A"
        )
        await sync_vulnerabilities_for_scan(session, scan1.id)

        # Kaybolma → oto-çözüm (erişilen host, top kapsam).
        scan2 = await create_scan(session, ScanType.network, "10.0.0.5")
        await _set_scan_window(session, scan2, started_at=T1, ports=None, target="10.0.0.5")
        await _set_asset_last_seen(session, asset, T1)
        await sync_vulnerabilities_for_scan(session, scan2.id)
        v = (await list_vulnerabilities(session, resolved=True))[0]
        assert v.status == FindingStatus.resolved

        # Yeniden tespit → reopened.
        scan3 = await create_scan(session, ScanType.network, "10.0.0.5")
        await create_finding(
            session, scan3.id, "A", severity=Severity.high, asset_id=asset.id, cve_id="CVE-A"
        )
        res = await sync_vulnerabilities_for_scan(session, scan3.id)
        assert res["reopened"] >= 1
        v2 = await get_vulnerability(session, v.id)
        assert v2 is not None
        assert v2.status == FindingStatus.open
        assert v2.reopened_count == 1
        assert v2.resolved_at is None


# 8 -------------------------------------------------------------------------
async def test_manual_triage_accepted_risk_persists_and_not_resolved(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """accepted_risk triyajı: bulgu tekrar görülünce KORUNUR; kaybolunca oto-çözülmez."""
    async with session_factory() as session:
        asset = await upsert_asset(session, "10.0.0.5")
        scan1 = await create_scan(session, ScanType.network, "10.0.0.5")
        await _set_scan_window(session, scan1, started_at=T0, ports=None, target="10.0.0.5")
        await _set_asset_last_seen(session, asset, T0)
        await create_finding(
            session, scan1.id, "A", severity=Severity.high, asset_id=asset.id, cve_id="CVE-A"
        )
        await sync_vulnerabilities_for_scan(session, scan1.id)
        v = (await list_vulnerabilities(session))[0]
        assert await set_vuln_status(session, v.id, FindingStatus.accepted_risk, note="kabul")

        # (a) Re-scan aynı fingerprint'i görür → accepted_risk korunur (open'a dönmez).
        scan2 = await create_scan(session, ScanType.network, "10.0.0.5")
        await _set_scan_window(session, scan2, started_at=T1, ports=None, target="10.0.0.5")
        await _set_asset_last_seen(session, asset, T1)
        await create_finding(
            session, scan2.id, "A", severity=Severity.high, asset_id=asset.id, cve_id="CVE-A"
        )
        await sync_vulnerabilities_for_scan(session, scan2.id)
        v2 = await get_vulnerability(session, v.id)
        assert v2 is not None
        assert v2.status == FindingStatus.accepted_risk

        # (b) Tam kapsam + erişilen host + bulgu YOK → yine korunur (yalnızca open çözülür).
        t2 = T1 + timedelta(hours=1)
        scan3 = await create_scan(session, ScanType.network, "10.0.0.5")
        await _set_scan_window(session, scan3, started_at=t2, ports=None, target="10.0.0.5")
        await _set_asset_last_seen(session, asset, t2)
        res = await sync_vulnerabilities_for_scan(session, scan3.id)
        assert res["resolved"] == 0
        v3 = await get_vulnerability(session, v.id)
        assert v3 is not None
        assert v3.status == FindingStatus.accepted_risk


# 9 -------------------------------------------------------------------------
async def test_confirmed_not_auto_resolved(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """M1: confirmed (analist doğruladı) tam kapsamlı re-scan'de oto-çözülmez."""
    async with session_factory() as session:
        asset = await upsert_asset(session, "10.0.0.5")
        scan1 = await create_scan(session, ScanType.network, "10.0.0.5")
        await _set_scan_window(session, scan1, started_at=T0, ports=None, target="10.0.0.5")
        await _set_asset_last_seen(session, asset, T0)
        await create_finding(
            session, scan1.id, "A", severity=Severity.high, asset_id=asset.id, cve_id="CVE-A"
        )
        await sync_vulnerabilities_for_scan(session, scan1.id)
        v = (await list_vulnerabilities(session))[0]
        assert await set_vuln_status(session, v.id, FindingStatus.confirmed)

        # Tam kapsam + erişilen host + bulgu yok → confirmed dokunulmaz.
        scan2 = await create_scan(session, ScanType.network, "10.0.0.5")
        await _set_scan_window(session, scan2, started_at=T1, ports=None, target="10.0.0.5")
        await _set_asset_last_seen(session, asset, T1)
        res = await sync_vulnerabilities_for_scan(session, scan2.id)
        assert res["resolved"] == 0
        v2 = await get_vulnerability(session, v.id)
        assert v2 is not None
        assert v2.status == FindingStatus.confirmed


# 10 ------------------------------------------------------------------------
async def test_fingerprint_stability(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """H1: parantezli oynak kısım fingerprint'ten çıkar; CVE > başlık; başlığa :svcN eklenir."""
    # Durum-kodu farkı (parantez içi) aynı fingerprint üretir → churn yok.
    assert finding_fingerprint(
        None, "Erişilebilir yol: /admin (HTTP 403)", None
    ) == finding_fingerprint(None, "Erişilebilir yol: /admin (HTTP 401)", None)
    # CVE varsa CVE öncelikli.
    assert finding_fingerprint("CVE-2021-1", "x", None) == "cve:CVE-2021-1"
    # service_id verilince başlık-bazlı fingerprint :svcN ile biter.
    assert finding_fingerprint(None, "Weak cipher", 7) == "title:weak cipher:svc7"
    # Büyük/küçük + boşluk normalizasyonu.
    assert finding_fingerprint(None, "WEAK  CIPHER", 3) == finding_fingerprint(
        None, "weak cipher", 3
    )


# 11 ------------------------------------------------------------------------
async def test_list_count_get_set_basic(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """list/count/get/set_vuln_status temel davranışı + resolved filtreleri."""
    async with session_factory() as session:
        asset = await upsert_asset(session, "10.0.0.5")
        scan = await create_scan(session, ScanType.network, "10.0.0.5")
        await create_finding(
            session,
            scan.id,
            "A",
            severity=Severity.high,
            asset_id=asset.id,
            cve_id="CVE-A",
            risk_score=8.0,
        )
        await create_finding(
            session,
            scan.id,
            "B",
            severity=Severity.low,
            asset_id=asset.id,
            cve_id="CVE-B",
            risk_score=2.0,
        )
        await sync_vulnerabilities_for_scan(session, scan.id)

        # count: toplam / açık / çözülen.
        assert await count_vulnerabilities(session) == 2
        assert await count_vulnerabilities(session, resolved=False) == 2
        assert await count_vulnerabilities(session, resolved=True) == 0

        # list: risk_score azalan sıralama.
        listed = await list_vulnerabilities(session)
        assert [v.risk_score for v in listed] == [8.0, 2.0]

        # severity + asset_id + limit/offset filtreleri.
        highs = await list_vulnerabilities(session, severity=Severity.high)
        assert len(highs) == 1 and highs[0].cve_id == "CVE-A"
        assert len(await list_vulnerabilities(session, asset_id=asset.id)) == 2
        assert len(await list_vulnerabilities(session, limit=1)) == 1
        assert (await list_vulnerabilities(session, offset=1))[0].risk_score == 2.0

        # set_vuln_status(resolved) → resolved_at set; resolved filtreleri ayrışır.
        target = listed[0]
        assert await set_vuln_status(
            session, target.id, FindingStatus.resolved, note="fixed", user_id=1
        )
        got = await get_vulnerability(session, target.id)
        assert got is not None
        assert got.status == FindingStatus.resolved
        assert got.resolved_at is not None
        assert got.note == "fixed"
        assert got.updated_by == 1
        # resolved=False artık çözüleni HARİÇ tutar; resolved=True yalnızca onu içerir.
        assert await count_vulnerabilities(session, resolved=True) == 1
        not_resolved = await list_vulnerabilities(session, resolved=False)
        assert target.id not in {v.id for v in not_resolved}
        only_resolved = await list_vulnerabilities(session, resolved=True)
        assert {v.id for v in only_resolved} == {target.id}

        # Çözülmüşten başka duruma geçince resolved_at temizlenir.
        assert await set_vuln_status(session, target.id, FindingStatus.confirmed)
        got2 = await get_vulnerability(session, target.id)
        assert got2 is not None
        assert got2.resolved_at is None

        # Olmayan id → False / None.
        assert await set_vuln_status(session, 99999, FindingStatus.open) is False
        assert await get_vulnerability(session, 99999) is None


# 12 ------------------------------------------------------------------------
async def test_lifecycle_stats_and_severity_open(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """vuln_lifecycle_stats + severity_counts_open: açık/çözülen/yeni/MTTR + önem dağılımı."""
    async with session_factory() as session:
        asset = await upsert_asset(session, "10.0.0.5")
        scan = await create_scan(session, ScanType.network, "10.0.0.5")
        for title, sev, cve in [
            ("A", Severity.critical, "CVE-A"),
            ("B", Severity.high, "CVE-B"),
            ("C", Severity.low, "CVE-C"),
        ]:
            await create_finding(
                session, scan.id, title, severity=sev, asset_id=asset.id, cve_id=cve
            )
        await sync_vulnerabilities_for_scan(session, scan.id)

        # severity_counts_open: 3 açık (1 critical, 1 high, 1 low).
        sev_open = await severity_counts_open(session)
        assert sev_open.get("critical") == 1
        assert sev_open.get("high") == 1
        assert sev_open.get("low") == 1

        # Başlangıç yaşam-döngüsü: 3 açık, 0 çözülen, 3 yeni (7g), MTTR yok.
        stats = await vuln_lifecycle_stats(session)
        assert stats["open"] == 3
        assert stats["resolved"] == 0
        assert stats["new_7d"] == 3
        assert stats["resolved_7d"] == 0
        assert stats["regressions"] == 0
        assert stats["mttr_days"] is None

        # Birini çöz → resolved/resolved_7d artar, MTTR hesaplanır (≥0 gün).
        v = (await list_vulnerabilities(session))[0]
        assert await set_vuln_status(session, v.id, FindingStatus.resolved)
        stats2 = await vuln_lifecycle_stats(session)
        assert stats2["open"] == 2
        assert stats2["resolved"] == 1
        assert stats2["resolved_7d"] == 1
        mttr = stats2["mttr_days"]
        assert mttr is not None
        assert mttr >= 0
        # severity_counts_open artık çözüleni hariç tutar (2 açık).
        sev_open2 = await severity_counts_open(session)
        assert sum(sev_open2.values()) == 2


# 13 ------------------------------------------------------------------------
async def test_validated_propagates_to_vulnerability(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """VI-13: validated bulgu → vuln.validated=True; çıkarım+doğrulanmış aynı CVE → True."""
    async with session_factory() as session:
        asset = await upsert_asset(session, "10.0.0.5")
        scan = await create_scan(session, ScanType.network, "10.0.0.5")
        # Aynı CVE için hem çıkarım (validated=False) hem NSE doğrulanmış (True) bulgu.
        await create_finding(
            session, scan.id, "A inf", severity=Severity.high, asset_id=asset.id, cve_id="CVE-A"
        )
        await create_finding(
            session,
            scan.id,
            "A nse",
            severity=Severity.high,
            asset_id=asset.id,
            cve_id="CVE-A",
            validated=True,
        )
        # Yalnız çıkarım olan ikinci CVE.
        await create_finding(
            session, scan.id, "B inf", severity=Severity.low, asset_id=asset.id, cve_id="CVE-B"
        )
        await sync_vulnerabilities_for_scan(session, scan.id)

        vulns = {v.cve_id: v for v in await list_vulnerabilities(session)}
        assert vulns["CVE-A"].validated is True  # yapışkan: doğrulanmış kazanır
        assert vulns["CVE-B"].validated is False  # yalnız çıkarım


# 14 ------------------------------------------------------------------------
async def test_vuln_trend(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """VI-3: vuln_trend haftalık açık/yeni/çözülen + aging + MTTR (first_seen/resolved_at'ten)."""
    now = datetime.now(UTC)
    async with session_factory() as session:
        asset = await upsert_asset(session, "10.0.0.5")

        def _v(fp: str, first: datetime, resolved: datetime | None) -> Vulnerability:
            return Vulnerability(
                asset_id=asset.id,
                fingerprint=fp,
                scan_type=ScanType.network,
                title=fp,
                severity=Severity.high,
                first_seen=first,
                last_seen=now,
                resolved_at=resolved,
                status=FindingStatus.resolved if resolved else FindingStatus.open,
            )

        session.add(_v("a", now - timedelta(days=20), None))  # açık, recent (8-30g)
        session.add(
            _v("b", now - timedelta(days=40), now - timedelta(days=35))
        )  # çözülmüş, mttr=5g
        session.add(_v("c", now - timedelta(days=3), None))  # açık, fresh (≤7g)
        await session.commit()

        trend = await vuln_trend(session, weeks=8)
        assert trend["open_total"] == 2
        assert trend["resolved_total"] == 1
        aging = trend["aging"]
        assert isinstance(aging, dict)
        assert aging["fresh"] == 1 and aging["recent"] == 1 and aging["old"] == 0
        assert trend["mttr_days"] == 5.0
        points = trend["points"]
        assert isinstance(points, list)
        assert len(points) == 8
        # En yeni hafta sonu (≈now) açık sayısı = 2 (a + c; b çözülmüş).
        assert points[-1]["open"] == 2
        # 8 hafta penceresinde 3 yeni (a,b,c) ve 1 çözülen (b).
        assert sum(p["new"] for p in points) == 3
        assert sum(p["resolved"] for p in points) == 1
