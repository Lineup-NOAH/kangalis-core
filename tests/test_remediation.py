"""Çözüm (remediation) üretimi testleri — saf mantık, oturum gerektirmez."""

from __future__ import annotations

from cybersectool.core.models import CVE, Finding, Service, Severity
from cybersectool.core.remediation import remediation_for


def _finding(title: str, cve_id: str | None = None) -> Finding:
    return Finding(title=title, cve_id=cve_id, severity=Severity.high)


def test_keyword_rule_smbv1() -> None:
    rem = remediation_for(_finding("SMBv1 etkin (MS17-010 riski)"))
    assert "SMBv1" in rem.summary
    assert rem.references == []  # CVE yok
    # NEDEN artık boş ("—") bırakılmaz; servis/CVE yoksa başlık-anahtarına göre anlamlı metin.
    assert rem.cause != "—"
    assert "SMBv1" in rem.cause


def test_cause_weak_credential_filled() -> None:
    """Servis/CVE bağlanmamış zayıf/varsayılan-kimlik bulgusunda NEDEN boş kalmaz."""
    rem = remediation_for(_finding("Varsayılan SSH kimliği: root/toor (172.28.0.21:22)"))
    assert rem.cause != "—"
    assert "kimlik" in rem.cause.lower()


def test_cause_generic_fallback_not_dash() -> None:
    """Tanınmayan, servis/CVE'siz bulguda bile NEDEN anlamlı (boş değil)."""
    rem = remediation_for(_finding("Genel mimari notu"))
    assert rem.cause != "—"
    assert rem.cause  # boş değil


def test_keyword_rule_tls() -> None:
    rem = remediation_for(_finding("Zayıf TLS cipher takımı"))
    assert "TLS" in rem.summary


def test_cve_template_when_no_rule() -> None:
    rem = remediation_for(_finding("Bilinmeyen zafiyet", cve_id="CVE-2024-1234"))
    assert "yama" in rem.summary.lower()
    # NVD linki referanslara eklenir
    assert "nvd.nist.gov/vuln/detail/CVE-2024-1234" in rem.references[0]


def test_generic_when_no_rule_no_cve() -> None:
    rem = remediation_for(_finding("Genel mimari notu"))
    assert rem.summary  # boş değil
    assert "yetki" in rem.summary.lower()


def test_kev_prefixes_urgency_and_epss_pct() -> None:
    cve = CVE(
        cve_id="CVE-2021-44228",
        references=["https://logging.apache.org/log4j"],
        kev_flag=True,
        epss_score=0.97,
        cvss_score=10.0,
    )
    rem = remediation_for(_finding("Log4Shell RCE", cve_id="CVE-2021-44228"), cve=cve)
    assert rem.summary.startswith("ACİL")
    assert rem.kev is True
    assert rem.epss_pct == "%97"
    # NVD linki + CVE referansı
    assert any("nvd.nist.gov" in r for r in rem.references)
    assert any("logging.apache.org" in r for r in rem.references)


def test_cause_includes_service_and_cve() -> None:
    svc = Service(product="OpenSSH", version="7.4", port=22, protocol="tcp")
    f = Finding(
        title="Eski OpenSSH", cve_id="CVE-2020-0001", severity=Severity.medium, service_id=5
    )
    rem = remediation_for(f, service=svc)
    assert "OpenSSH 7.4" in rem.cause
    assert "22/tcp" in rem.cause
    assert "CVE-2020-0001" in rem.cause


def test_references_capped_at_six() -> None:
    cve = CVE(
        cve_id="CVE-2024-9999",
        references=[f"https://ref{i}.example" for i in range(20)],
    )
    rem = remediation_for(_finding("x", cve_id="CVE-2024-9999"), cve=cve)
    assert len(rem.references) == 6  # NVD + 5 referans (sınır)
