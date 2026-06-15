"""CVE → uyum/mevzuat heuristik eşlemesi (IX-10) — SAF birim testleri."""

from __future__ import annotations

from cybersectool.core.cve_compliance import FRAMEWORKS, frameworks_for_cve


def test_result_keeps_framework_order_and_unique() -> None:
    fws = frameworks_for_cve(title="SQL injection in login form", severity="high")
    assert fws == [f for f in FRAMEWORKS if f in fws]  # FRAMEWORKS sırası
    assert len(fws) == len(set(fws))  # tekrarsız


def test_crypto_maps_pci_iso_kvkk() -> None:
    fws = frameworks_for_cve(title="OpenSSL TLS heartbleed information disclosure")
    assert "PCI-DSS" in fws and "ISO 27001" in fws and "KVKK" in fws


def test_sql_injection_maps_pci_nist() -> None:
    fws = frameworks_for_cve(title="SQL injection allows data theft", severity="critical")
    assert "PCI-DSS" in fws and "NIST CSF" in fws


def test_logging_maps_5651() -> None:
    assert "5651" in frameworks_for_cve(title="Insufficient logging of access events")


def test_web_xss_maps_pci_kvkk() -> None:
    fws = frameworks_for_cve(title="Stored XSS in comment field", severity="medium")
    assert "PCI-DSS" in fws and "KVKK" in fws


def test_category_database_maps() -> None:
    fws = frameworks_for_cve(title="generic bug", categories=["database"], severity="low")
    assert "PCI-DSS" in fws and "KVKK" in fws


def test_serious_adds_core_frameworks() -> None:
    # Anahtar kelime yok ama KEV → çekirdek çerçeveler eklenir.
    assert {"KVKK", "ISO 27001", "PCI-DSS"}.issubset(frameworks_for_cve(title="overflow", kev=True))
    # CVSS>=7 de ciddi sayılır → boş değil.
    assert frameworks_for_cve(title="x", cvss_score=9.8)


def test_low_severity_no_keyword_returns_empty() -> None:
    # Düşük önem + eşleşen kelime/kategori yok → rozet yok (temiz, düşük FP).
    assert frameworks_for_cve(title="cosmetic ui glitch", severity="low") == []
