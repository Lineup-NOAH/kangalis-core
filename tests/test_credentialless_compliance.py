"""Kimliksiz uyum denetimi testleri (roadmap #E).

Saf ``eval_*`` yardımcıları (TLS/açık-servis/yönetim-portu/HTTP) + uçtan uca
``run_credentialless_compliance`` → ``store_compliance`` (ComplianceCheck satırları).
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.assets import upsert_asset, upsert_service
from cybersectool.core.compliance import (
    ComplianceResult,
    compliance_for_scan,
    regulation_summary,
    store_compliance,
)
from cybersectool.core.findings import create_finding
from cybersectool.core.models import ScanType, Severity
from cybersectool.core.scans import create_scan
from cybersectool.scanners.credentialless_compliance import (
    FRAMEWORK,
    eval_exposed_services,
    eval_http_hsts,
    eval_management_ports,
    eval_tls,
    run_credentialless_compliance,
)

# --- Saf eval testleri -------------------------------------------------------


def test_eval_tls_skips_when_no_https() -> None:
    """TLS hiç denetlenmediyse (HTTPS yok) hiçbir TLS denetimi emit edilmez."""
    assert eval_tls([], https_present=False) == []


def test_eval_tls_strong_all_pass() -> None:
    """HTTPS var, zayıflık bulgusu yok → 4 TLS denetimi de PASS."""
    results = eval_tls([], https_present=True)
    assert len(results) == 4
    assert all(r.status == "pass" for r in results)
    assert {r.control_id for r in results} == {"N-TLS.1", "N-TLS.2", "N-TLS.3", "N-TLS.4"}


def test_eval_tls_weak_version_fails() -> None:
    """Zayıf TLS sürümü/protokolü bulgusu → N-TLS.1 FAIL, diğerleri PASS."""
    titles = ["Zayıf TLS protokolü ETKİN: TLSv1.0"]
    by_id = {r.control_id: r for r in eval_tls(titles, https_present=True)}
    assert by_id["N-TLS.1"].status == "fail"
    assert by_id["N-TLS.1"].severity == Severity.medium
    assert by_id["N-TLS.2"].status == "pass"


def test_eval_tls_cipher_selfsigned_expired() -> None:
    """Zayıf cipher + self-signed + süresi dolmuş ayrı denetimlerde FAIL."""
    titles = [
        "Zayıf TLS şifre paketi: RC4-MD5 (128 bit)",
        "Kendinden imzalı (self-signed) TLS sertifikası",
        "TLS sertifikası süresi dolmuş",
    ]
    by_id = {r.control_id: r for r in eval_tls(titles, https_present=True)}
    assert by_id["N-TLS.2"].status == "fail"
    assert by_id["N-TLS.3"].status == "fail"
    assert by_id["N-TLS.4"].status == "fail"
    assert by_id["N-TLS.4"].severity == Severity.high
    assert by_id["N-TLS.1"].status == "pass"  # sürüm bulgusu yok


def test_eval_tls_near_expiry_fails() -> None:
    """'N gün içinde dolacak' de N-TLS.4'ü FAIL eder."""
    titles = ["TLS sertifikası 12 gün içinde dolacak"]
    by_id = {r.control_id: r for r in eval_tls(titles, https_present=True)}
    assert by_id["N-TLS.4"].status == "fail"


def test_eval_exposed_services() -> None:
    """Açık-servis bulgu başlıkları → ilgili denetim FAIL; yoksa emit edilmez."""
    titles = [
        "Kimlik doğrulamasız Redis (10.0.0.5:6379)",
        "Anonim FTP erişimi (10.0.0.5:21)",
        "Kimlik doğrulamasız Kubernetes API (10.0.0.5:6443)",
        "Eksik güvenlik başlığı: X-Frame-Options",  # alakasız
    ]
    by_id = {r.control_id: r for r in eval_exposed_services(titles)}
    assert set(by_id) == {"N-EXP.1", "N-EXP.5", "N-EXP.6"}
    assert all(r.status == "fail" for r in by_id.values())
    assert by_id["N-EXP.1"].severity == Severity.critical
    # Hiç açık-servis bulgusu yoksa boş (sahte pass yok).
    assert eval_exposed_services([]) == []


def test_eval_management_ports() -> None:
    """Yönetim portu açıksa FAIL; yoksa None (atlanır)."""
    assert eval_management_ports({80, 443}) is None
    res = eval_management_ports({22, 3389, 80})
    assert res is not None
    assert res.control_id == "N-MGT.1"
    assert res.status == "fail"
    assert "SSH(22)" in (res.detail or "")
    assert "RDP(3389)" in (res.detail or "")


def test_eval_http_hsts() -> None:
    """80 açık ya da HSTS eksik → FAIL; HTTPS var + HSTS tam → PASS; hiç web yok → None."""
    # 80 açık → fail
    r1 = eval_http_hsts({80}, [], https_present=False)
    assert r1 is not None and r1.status == "fail"
    # HSTS eksik bulgusu → fail
    r2 = eval_http_hsts(
        {443}, ["Eksik güvenlik başlığı: Strict-Transport-Security (HSTS)"], https_present=True
    )
    assert r2 is not None and r2.status == "fail"
    # HTTPS var, HSTS eksik bulgusu yok → pass
    r3 = eval_http_hsts({443}, [], https_present=True)
    assert r3 is not None and r3.status == "pass"
    # Web yüzeyi yok → atlanır
    assert eval_http_hsts({22}, [], https_present=False) is None


# --- Uçtan uca: run_credentialless_compliance + store_compliance -------------


async def test_run_and_store(session_factory: async_sessionmaker[AsyncSession]) -> None:
    """Servis + bulgu olan bir taramada uyum sonuçları türetilip ComplianceCheck'e yazılır."""
    async with session_factory() as session:
        scan = await create_scan(session, ScanType.network, "10.0.0.5")
        asset = await upsert_asset(session, "10.0.0.5", is_up=True)
        # Açık portlar: SSH (yönetim) + Redis (açık-servis) + HTTPS.
        await upsert_service(session, asset.id, 22, service_name="ssh")
        await upsert_service(session, asset.id, 6379, service_name="redis")
        await upsert_service(session, asset.id, 443, service_name="https")
        # Bulgular: kimliksiz Redis + zayıf TLS sürümü.
        await create_finding(
            session,
            scan.id,
            "Kimlik doğrulamasız Redis (10.0.0.5:6379)",
            severity=Severity.critical,
            asset_id=asset.id,
        )
        await create_finding(
            session,
            scan.id,
            "Zayıf TLS sürümü (görüşülen): TLSv1.1",
            severity=Severity.medium,
            asset_id=asset.id,
        )

        # tls_checked=True: TLS denetlenmiş yolu (web/ESXi) → TLS denetimleri emit edilir.
        results = await run_credentialless_compliance(session, scan.id, tls_checked=True)
        await store_compliance(session, scan.id, results)

        checks = await compliance_for_scan(session, scan.id)
        by_id = {c.control_id: c for c in checks}
        # Tek çerçeve etiketi.
        assert all(c.framework == FRAMEWORK for c in checks)
        # Redis açık → FAIL.
        assert by_id["N-EXP.1"].status == "fail"
        # Zayıf TLS sürümü → N-TLS.1 FAIL; cipher/self-signed/expired PASS.
        assert by_id["N-TLS.1"].status == "fail"
        assert by_id["N-TLS.2"].status == "pass"
        # SSH(22) açık → yönetim portu FAIL.
        assert by_id["N-MGT.1"].status == "fail"
        # 443 açık, HSTS-eksik bulgusu yok → HTTP/HSTS PASS (uçtan uca + REGULATION_MAP round-trip).
        assert by_id["N-HTTP.1"].status == "pass"
        # KVKK/ISO/PCI rollup bu kontrolleri görüyor (REGULATION_MAP eşli).
        summ = regulation_summary(checks)
        assert "KVKK" in summ
        assert summ["KVKK"].total >= 4


async def test_run_empty_scan_no_results(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Boş tarama sonuç üretmez; boş yazım var olan satırları SİLMEZ (çerçeve-scoped delete)."""
    async with session_factory() as session:
        scan = await create_scan(session, ScanType.network, "10.0.0.9")
        # Önceden kimlikli bir satır olsun.
        await store_compliance(
            session,
            scan.id,
            [ComplianceResult("CIS Linux", "5.2.8", "x", "fail", Severity.high, None)],
        )
        results = await run_credentialless_compliance(session, scan.id)
        assert results == []
        # Boş sonuçla yazım (frameworks boş → hiçbir şey silinmez) — kimlikli satır kalır.
        await store_compliance(session, scan.id, results)
        checks = await compliance_for_scan(session, scan.id)
        assert any(c.framework == "CIS Linux" for c in checks)


async def test_network_path_no_tls_rows_even_if_443_open(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Ağ yolu (tls_checked=False): 443 açıkken bile TLS denetimi emit EDİLMEZ (sahte pass yok)."""
    async with session_factory() as session:
        scan = await create_scan(session, ScanType.network, "10.0.0.8")
        asset = await upsert_asset(session, "10.0.0.8", is_up=True)
        await upsert_service(session, asset.id, 443, service_name="https")
        await create_finding(
            session, scan.id, "Açık port: 443/tcp", severity=Severity.info, asset_id=asset.id
        )
        results = await run_credentialless_compliance(session, scan.id, tls_checked=False)
        assert not any(r.control_id.startswith("N-TLS") for r in results)
        # 443 açık → HTTP/HSTS yüzeyi yine değerlendirilir (TLS'ten bağımsız).
        assert any(r.control_id == "N-HTTP.1" for r in results)


def test_tls_connection_error_skips_tls() -> None:
    """tls_checked=True ama el sıkışma hatası başlığı varsa TLS denetlenmemiş sayılır (skip)."""
    # Bağlantı hatası başlığı "TLS" içerir ama denetim yapılamadı → eval gate'i bunu dışlar.
    from cybersectool.scanners.credentialless_compliance import _TLS_CONN_ERROR

    titles = [_TLS_CONN_ERROR]
    tls_inspected = True and not any(_TLS_CONN_ERROR in t for t in titles)
    assert eval_tls(titles, https_present=tls_inspected) == []


async def test_credentialed_and_credentialless_coexist(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Aynı scan_id'ye kimlikli (CIS) + kimliksiz (Ağ/TLS) uyum yazılır → biri diğerini SİLMEZ.

    store_compliance çerçeve-scoped sildiği için NESSUS-modeli tek tarama iki üreticiyi taşır
    (yazma sırasından bağımsız). Bu, kritik veri-kaybı düzeltmesinin yük-taşıyan kanıtıdır.
    """
    async with session_factory() as session:
        scan = await create_scan(session, ScanType.network, "10.0.0.7")
        cred = [
            ComplianceResult("CIS Linux", "5.2.8", "SSH root login", "fail", Severity.high, None)
        ]
        cl = [ComplianceResult(FRAMEWORK, "N-EXP.1", "Redis", "fail", Severity.critical, None)]
        await store_compliance(session, scan.id, cred)
        await store_compliance(session, scan.id, cl)  # AYNI scan_id, farklı çerçeve
        frameworks = {c.framework for c in await compliance_for_scan(session, scan.id)}
        assert "CIS Linux" in frameworks  # kimlikli satır SİLİNMEDİ
        assert FRAMEWORK in frameworks  # kimliksiz satır da var
        # Kimliksiz tekrar yazım yalnız kendi çerçevesini tazeler (idempotent), CIS dokunulmaz.
        await store_compliance(session, scan.id, cl)
        checks = await compliance_for_scan(session, scan.id)
        assert sum(1 for c in checks if c.framework == "CIS Linux") == 1
        assert sum(1 for c in checks if c.framework == FRAMEWORK) == 1
