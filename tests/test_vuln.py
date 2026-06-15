"""CVE eşleştirme (NVD) testleri."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core import vuln
from cybersectool.core.assets import upsert_asset, upsert_service
from cybersectool.core.findings import count_open_findings
from cybersectool.core.models import CVE, ScanType, Service, Severity
from cybersectool.core.scans import create_scan
from cybersectool.intel.nvd import CveData, parse_nvd_response

SAMPLE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-1234",
                "descriptions": [{"lang": "en", "value": "Sample flaw"}],
                "metrics": {
                    "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]
                },
                "references": [{"url": "https://example.com/a"}],
            }
        }
    ]
}


def test_clean_version_keeps_letter_suffix() -> None:
    """DÜŞÜK fix: numaraya bitişik harf-sonek korunur (1.0.1f) ama boşluklu ek metin atılır.

    Eskiden regex harf-soneki kırpıyordu (1.0.1f → 1.0.1) → CPE tam-sürüm '1.0.1f' eşleşmesi kaçar.
    """
    assert vuln._clean_version("1.0.1f") == "1.0.1f"
    assert vuln._clean_version("OpenSSL 1.0.1f-fips") == "1.0.1f"
    assert vuln._clean_version("2.4.49 (Ubuntu)") == "2.4.49"  # boşluklu ek metin dışarıda
    assert vuln._clean_version("Apache/2.4.49") == "2.4.49"
    assert vuln._clean_version("") == ""
    assert vuln._clean_version(None) == ""


def test_parse_nvd_response() -> None:
    cves = parse_nvd_response(SAMPLE)
    assert len(cves) == 1
    assert cves[0].cve_id == "CVE-2021-1234"
    assert cves[0].cvss_score == 9.8
    assert cves[0].severity == Severity.critical
    assert cves[0].references == ["https://example.com/a"]


def test_parse_nvd_response_skips_rejected() -> None:
    """#137: vulnStatus == 'Rejected' CVE'ler atlanır (geçersiz zafiyet yazılmaz)."""
    data = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2020-REJECT",
                    "vulnStatus": "Rejected",
                    "descriptions": [{"lang": "en", "value": "** REJECT ** not a vuln"}],
                    "metrics": {},
                }
            },
            {
                "cve": {
                    "id": "CVE-2020-VALID",
                    "vulnStatus": "Analyzed",
                    "descriptions": [{"lang": "en", "value": "real flaw"}],
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]
                    },
                }
            },
        ]
    }
    cves = parse_nvd_response(data)
    ids = {c.cve_id for c in cves}
    assert "CVE-2020-VALID" in ids
    assert "CVE-2020-REJECT" not in ids  # reddedilmiş → atlandı


def test_parse_nvd_response_cvss_v4_only() -> None:
    """#136: Yalnız CVSS v4.0 metriği olan CVE skorsuz kalmaz (v4 parse edilir)."""
    data = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-9999",
                    "descriptions": [{"lang": "en", "value": "v4 only"}],
                    "metrics": {
                        "cvssMetricV40": [{"cvssData": {"baseScore": 8.7, "baseSeverity": "HIGH"}}]
                    },
                }
            }
        ]
    }
    cves = parse_nvd_response(data)
    assert cves[0].cvss_score == 8.7
    assert cves[0].severity == Severity.high


def test_parse_nvd_response_prefers_primary() -> None:
    """#136: Aynı metrikte Primary (NVD) sağlayıcı yeğlenir (Secondary değil)."""
    data = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2023-1",
                    "descriptions": [{"lang": "en", "value": "x"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "type": "Secondary",
                                "cvssData": {"baseScore": 3.1, "baseSeverity": "LOW"},
                            },
                            {
                                "type": "Primary",
                                "cvssData": {"baseScore": 9.1, "baseSeverity": "CRITICAL"},
                            },
                        ]
                    },
                }
            }
        ]
    }
    cves = parse_nvd_response(data)
    assert cves[0].cvss_score == 9.1  # Primary, Secondary (3.1) değil
    assert cves[0].severity == Severity.critical


def test_service_keyword() -> None:
    svc = Service(
        asset_id=1, port=5432, protocol="tcp", product="PostgreSQL DB", version="9.6.0 or later"
    )
    assert vuln.service_keyword(svc) == "PostgreSQL 9.6.0"
    assert vuln.service_keyword(Service(asset_id=1, port=1, protocol="tcp")) is None


async def test_match_service_cves(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Canlı NVD eşleşmesi YALNIZ servisin sürümüne CPE olarak uygulanan CVE'leri bulguya çevirir.

    Keyword araması açıklamada gevşek eşleştiği için başka-sürüm/CPE'siz CVE'leri de döndürür;
    bunlar yanlış-pozitif gürültüsü olarak süzülmeli (servis OpenSSH 7.2).
    """
    from cybersectool.intel.cpe import CpeMatchData

    def _cpe(vendor: str, product: str, **bounds: str) -> CpeMatchData:
        return CpeMatchData(
            criteria=f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*",
            part="a",
            vendor=vendor,
            product=product,
            version="*",
            vulnerable=True,
            **bounds,
        )

    async def fake_fetch(keyword: str, limit: int = 10) -> list[CveData]:
        return [
            # Uygulanır: openssh ≤ 7.4 → servis 7.2 etkilenir → bulgu.
            CveData(
                cve_id="CVE-2021-1234",
                description="x",
                cvss_score=9.8,
                severity=Severity.critical,
                cpe_matches=[_cpe("openbsd", "openssh", version_end_including="7.4")],
            ),
            # Uygulanmaz: yalnız ≤ 6.9 → servis 7.2 ETKİLENMEZ (yanlış-pozitif, süzülmeli).
            CveData(
                cve_id="CVE-2018-9999",
                description="eski",
                cvss_score=7.5,
                severity=Severity.high,
                cpe_matches=[_cpe("openbsd", "openssh", version_end_including="6.9")],
            ),
            # CPE konfigürasyonu yok (yalnız açıklamada geçiyor) → doğrulanamaz → süzülmeli.
            CveData(
                cve_id="CVE-2020-0000",
                description="openssh mention",
                severity=Severity.medium,
            ),
        ]

    monkeypatch.setattr(vuln, "fetch_cves", fake_fetch)
    async with session_factory() as session:
        asset = await upsert_asset(session, "10.0.0.10")
        service = await upsert_service(session, asset.id, 22, product="OpenSSH", version="7.2")
        scan = await create_scan(session, ScanType.network, "10.0.0.10")

        matched = await vuln.match_service_cves(session, scan.id, service)
        assert matched == ["CVE-2021-1234"]  # yalnız sürüme uygulanan CVE
        assert await count_open_findings(session) == 1
        cve = await session.get(CVE, "CVE-2021-1234")
        assert cve is not None
        assert cve.severity == Severity.critical


async def test_apply_risk_scores_exploit_signal(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """VI-1: apply_risk_scores Metasploit sinyalini (+1.5) Finding VE Vulnerability'ye uygular."""
    from cybersectool.core.findings import create_finding
    from cybersectool.core.models import Exploit, ExploitSource, FindingStatus, Vulnerability

    async with session_factory() as session:
        asset = await upsert_asset(session, "10.0.0.50")
        scan = await create_scan(session, ScanType.network, "10.0.0.50")
        session.add(CVE(cve_id="CVE-2021-9999", cvss_score=5.0, epss_score=None, kev_flag=False))
        session.add(
            Exploit(
                source=ExploitSource.metasploit,
                external_id="exploit/windows/test",
                title="Test MSF module",
                cve_text="CVE-2021-9999",
            )
        )
        await session.commit()
        finding = await create_finding(
            session,
            scan.id,
            "x",
            severity=Severity.medium,
            asset_id=asset.id,
            cve_id="CVE-2021-9999",
            risk_score=5.0,
        )
        vrow = Vulnerability(
            asset_id=asset.id,
            fingerprint="cve:CVE-2021-9999",
            scan_type=ScanType.network,
            title="x",
            severity=Severity.medium,
            cve_id="CVE-2021-9999",
            risk_score=5.0,
            status=FindingStatus.open,
        )
        session.add(vrow)
        await session.commit()

        await vuln.apply_risk_scores(session, ["CVE-2021-9999"])
        await session.refresh(finding)
        # 5.0 taban + 1.5 (silahlandırılmış/Metasploit) = 6.5; Finding + Vulnerability ikisi de.
        assert finding.risk_score == 6.5
        refreshed = await session.get(Vulnerability, vrow.id)
        assert refreshed is not None
        assert refreshed.risk_score == 6.5
