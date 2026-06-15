"""Uyum/benchmark motoru testleri (VII-1a)."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.compliance import (
    compliance_for_scan,
    compliance_overview,
    compliance_summary,
    derive_compliance,
    regulation_summary,
    store_compliance,
    top_failed_controls,
)
from cybersectool.core.models import ComplianceCheck, ScanType, Severity
from cybersectool.core.scans import create_scan


def test_regulation_summary() -> None:
    """VII-1c: CIS sonuçları KVKK/ISO/PCI maddelerine eşlenir; eşlemesiz CIS hariç tutulur."""
    checks = [
        ComplianceCheck(
            scan_id=1, framework="CIS Linux", control_id="5.2.8", title="SSH root", status="fail"
        ),
        ComplianceCheck(
            scan_id=1, framework="CIS Linux", control_id="1.1.2", title="sticky", status="pass"
        ),
        ComplianceCheck(
            scan_id=1, framework="CIS Linux", control_id="UNMAPPED", title="x", status="fail"
        ),
    ]
    summ = regulation_summary(checks)
    assert set(summ) == {"KVKK", "ISO 27001", "PCI-DSS"}
    kvkk = summ["KVKK"]
    assert kvkk.total == 2  # eşlemesiz CIS hariç
    assert kvkk.passed == 1 and kvkk.failed == 1
    assert kvkk.score == 50
    assert {c["cis_id"] for c in kvkk.controls} == {"5.2.8", "1.1.2"}
    # Boş regülasyon dönmez (hiç eşleşme yoksa).
    assert regulation_summary([]) == {}


def test_all_hardening_checks_mapped_to_cis() -> None:
    """VII-1b: TÜM Linux+Windows sertleştirme denetimleri bir CIS kontrolüne eşlenmiş olmalı."""
    from cybersectool.core.compliance import HARDENING_TO_CONTROL
    from cybersectool.scanners.credentialed import AUTH_CHECKS
    from cybersectool.scanners.hardening import CHECKS
    from cybersectool.scanners.winrm import WIN_CHECKS

    for check in (*CHECKS, *AUTH_CHECKS, *WIN_CHECKS):
        assert check.title in HARDENING_TO_CONTROL, f"eşlemesiz denetim: {check.title}"
    # Linux + Windows çerçeveleri kapsanır.
    frameworks = {c.framework for c in HARDENING_TO_CONTROL.values()}
    assert "CIS Linux" in frameworks
    assert "CIS Windows" in frameworks


def test_derive_compliance_pass_fail() -> None:
    """Çalışan denetimler kontrollere eşlenir; bulgulu=kaldı, bulgusuz=geçti; eşsiz atlanır."""
    ran = ["SSH root girişi", "/tmp sticky bit", "Eşlemesi olmayan denetim"]
    failed = {"SSH root girişi": (Severity.high, "root açık")}
    results = derive_compliance(ran, failed)
    assert len(results) == 2  # eşlemesi olmayan atlandı
    by_id = {r.control_id: r for r in results}
    assert by_id["5.2.8"].status == "fail"
    assert by_id["5.2.8"].severity == Severity.high
    assert by_id["5.2.8"].framework == "CIS Linux"
    assert by_id["1.1.2"].status == "pass"
    assert by_id["1.1.2"].severity is None


async def test_store_query_summary(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """store_compliance + compliance_for_scan + compliance_summary (skor) + idempotentlik."""
    async with session_factory() as session:
        scan = await create_scan(session, ScanType.credentialed, "10.0.0.5")
        ran = ["SSH root girişi", "/tmp sticky bit"]
        failed = {"SSH root girişi": (Severity.high, "x")}
        n = await store_compliance(session, scan.id, derive_compliance(ran, failed))
        assert n == 2

        checks = await compliance_for_scan(session, scan.id)
        assert len(checks) == 2

        summ = await compliance_summary(session, scan.id)
        assert summ["CIS Linux"]["pass"] == 1
        assert summ["CIS Linux"]["fail"] == 1
        assert summ["CIS Linux"]["total"] == 2
        assert summ["CIS Linux"]["score"] == 50

        # Idempotent: yeniden saklama eskileri siler (kopya üretmez).
        await store_compliance(session, scan.id, derive_compliance(["/tmp sticky bit"], {}))
        again = await compliance_for_scan(session, scan.id)
        assert len(again) == 1
        assert again[0].status == "pass"


async def test_compliance_overview_and_failed_controls(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """X-4: tüm taramalar geneli çerçeve özeti + en çok başarısız kontrol listesi."""
    async with session_factory() as session:
        s1 = await create_scan(session, ScanType.credentialed, "10.0.0.5")
        s2 = await create_scan(session, ScanType.credentialed, "10.0.0.6")
        # İki taramada da SSH root girişi KALDI (aynı kontrol) → fails=2.
        fail = {"SSH root girişi": (Severity.high, "x")}
        await store_compliance(
            session, s1.id, derive_compliance(["SSH root girişi", "/tmp sticky bit"], fail)
        )
        await store_compliance(session, s2.id, derive_compliance(["SSH root girişi"], fail))

        ov = await compliance_overview(session)
        # CIS Linux: 1 pass (/tmp) + 2 fail (root×2) = 3 total → skor=33.
        assert ov["CIS Linux"]["pass"] == 1
        assert ov["CIS Linux"]["fail"] == 2
        assert ov["CIS Linux"]["total"] == 3
        assert ov["CIS Linux"]["score"] == 33

        failed = await top_failed_controls(session)
        top = failed[0]
        assert top["control_id"] == "5.2.8"  # SSH root
        assert top["fails"] == 2
        assert top["framework"] == "CIS Linux"
