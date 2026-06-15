"""Zafiyet kategorisi (VULN-CAT): saf türetim + sync doldurma + oto-çözüm guard + filtre."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.assets import upsert_asset
from cybersectool.core.findings import create_finding
from cybersectool.core.models import ScanType, Severity
from cybersectool.core.scans import create_scan
from cybersectool.core.vuln_category import (
    CONFIG,
    CVE,
    OS_PACKAGE,
    OTHER,
    WEAK_CREDENTIAL,
    WEB,
    derive_vuln_category,
    is_os_package_title,
    is_weak_credential_title,
)
from cybersectool.core.vulnerabilities import (
    category_counts,
    count_vulnerabilities,
    list_vulnerabilities,
    list_vulnerabilities_page,
    sync_vulnerabilities_for_scan,
)


def test_derive_vuln_category() -> None:
    # Zayıf/varsayılan kimlik başlıkları → weak_credential (en yüksek öncelik, CVE'siz).
    assert is_weak_credential_title("Zayıf/varsayılan kimlik bulundu (SSH): root")
    assert is_weak_credential_title("Varsayılan SSH kimliği: admin/admin (10.0.0.5:22)")
    assert (
        derive_vuln_category(
            "Zayıf/varsayılan kimlik bulundu (SMB): admin", ScanType.credentialed, None
        )
        == WEAK_CREDENTIAL
    )
    # CVE'li bulgu → cve.
    assert derive_vuln_category("OpenSSH RCE", ScanType.network, "CVE-2024-1234") == CVE
    # OS-paket bulgusu (OSV.dev) → os_package, CVE'si OLSA bile (cve'den önce gelir).
    assert is_os_package_title("Zafiyetli paket: openssl 1.1.1n (CVE-2022-0001)")
    assert not is_os_package_title("OpenSSH RCE")
    assert (
        derive_vuln_category(
            "Zafiyetli paket: openssl 1.1.1n (CVE-2022-0001)",
            ScanType.credentialed,
            "CVE-2022-0001",
        )
        == OS_PACKAGE
    )
    # Web/config/other.
    assert derive_vuln_category("Eksik güvenlik başlığı: CSP", ScanType.web, None) == WEB
    assert derive_vuln_category("SMB imzalama", ScanType.credentialed, None) == CONFIG
    assert derive_vuln_category("Açık port", ScanType.network, None) == OTHER


async def test_sync_sets_category(session_factory: async_sessionmaker[AsyncSession]) -> None:
    async with session_factory() as session:
        asset = await upsert_asset(session, "10.0.0.5", is_up=True)
        scan = await create_scan(session, ScanType.credentialed, "10.0.0.5", ports="top")
        await create_finding(
            session,
            scan.id,
            "Zayıf/varsayılan kimlik bulundu (SSH): root",
            severity=Severity.critical,
            asset_id=asset.id,
        )
        await sync_vulnerabilities_for_scan(session, scan.id)
        vulns = await list_vulnerabilities(session)
        assert len(vulns) == 1
        assert vulns[0].category == WEAK_CREDENTIAL
        assert vulns[0].severity == Severity.critical


async def test_weak_credential_vuln_not_auto_resolved(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Zayıf-kimlik vuln'ü, aynı asset'te sonraki bir credentialed tarama onu içermese
    bile OTO-ÇÖZÜLMEZ (örn. SMB denetimi brute-force kimlik bulgusunu çözmemeli)."""
    async with session_factory() as session:
        asset = await upsert_asset(session, "10.0.0.5", is_up=True)
        # 1) Brute benzeri hedefli tarama (ports=targeted → coverage 0) zayıf-kimlik bulur.
        brute = await create_scan(session, ScanType.credentialed, "10.0.0.5", ports="targeted")
        await create_finding(
            session,
            brute.id,
            "Zayıf/varsayılan kimlik bulundu (SSH): root",
            severity=Severity.critical,
            asset_id=asset.id,
        )
        await sync_vulnerabilities_for_scan(session, brute.id)
        assert await count_vulnerabilities(session, resolved=False, category=WEAK_CREDENTIAL) == 1

        # 2) Sonraki SMB denetimi (aynı asset, top portlar) farklı bulgu üretir;
        #    zayıf-kimlik vuln'ünü içermez ama onu ÇÖZMEMELİDİR.
        smb = await create_scan(session, ScanType.credentialed, "10.0.0.5", ports="top")
        await create_finding(
            session, smb.id, "SMB imzalama", severity=Severity.medium, asset_id=asset.id
        )
        await sync_vulnerabilities_for_scan(session, smb.id)
        # Zayıf-kimlik hâlâ AÇIK (oto-çözülmedi).
        assert await count_vulnerabilities(session, resolved=False, category=WEAK_CREDENTIAL) == 1


async def test_category_filter_and_counts(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        a1 = await upsert_asset(session, "10.0.0.5", is_up=True)
        scan = await create_scan(session, ScanType.network, "10.0.0.5", ports="top")
        await create_finding(
            session,
            scan.id,
            "Zayıf/varsayılan kimlik bulundu (SSH): root",
            severity=Severity.critical,
            asset_id=a1.id,
        )
        await create_finding(
            session, scan.id, "Açık port 23/telnet", severity=Severity.low, asset_id=a1.id
        )
        await sync_vulnerabilities_for_scan(session, scan.id)
        counts = await category_counts(session, resolved=False)
        assert counts.get(WEAK_CREDENTIAL) == 1
        assert counts.get(OTHER) == 1
        # Kategori filtresi yalnız o kategoriyi döndürür.
        weak = await list_vulnerabilities_page(
            session, resolved=False, per=10, page=1, category=WEAK_CREDENTIAL
        )
        assert len(weak) == 1 and weak[0].category == WEAK_CREDENTIAL
