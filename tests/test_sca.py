"""SCA bağımlılık ayrıştırma + OSV yanıt ayrıştırma testleri."""

from __future__ import annotations

from cybersectool.intel.osv import parse_osv_response
from cybersectool.scanners.sca import parse_package_json, parse_requirements


def test_parse_requirements() -> None:
    content = (
        "# yorum\n"
        "Django==2.2.0\n"
        "requests>=2.0\n"
        "flask == 1.0.0\n"
        "-e .\n"
        "idna==3.4 ; python_version > '3'\n"
    )
    deps = parse_requirements(content)
    assert ("Django", "2.2.0") in deps
    assert ("flask", "1.0.0") in deps
    assert ("idna", "3.4") in deps
    assert all(name != "requests" for name, _ in deps)  # sabitlenmemiş → atlanır


def test_parse_package_json() -> None:
    content = '{"dependencies": {"lodash": "^4.17.0"}, "devDependencies": {"jest": "~29.0.0"}}'
    deps = parse_package_json(content)
    assert ("lodash", "4.17.0") in deps
    assert ("jest", "29.0.0") in deps


def test_parse_osv_response() -> None:
    data = {"vulns": [{"id": "GHSA-abcd", "summary": "flaw", "aliases": ["CVE-2021-1", "PYSEC-1"]}]}
    vulns = parse_osv_response(data)
    assert len(vulns) == 1
    assert vulns[0].id == "GHSA-abcd"
    assert vulns[0].cve == "CVE-2021-1"


def test_parse_osv_response_reads_real_severity() -> None:
    """DÜŞÜK fix: /v1/query yanıtındaki gerçek önem okunur (eskiden tüm OSV/SCA bulguları medium).

    ``database_specific.severity`` yoksa medium'a düşer (önceki davranışla uyumlu).
    """
    from cybersectool.core.models import Severity

    data = {
        "vulns": [
            {
                "id": "GHSA-high",
                "database_specific": {"severity": "HIGH"},
                "aliases": ["CVE-2021-9"],
            },
            {"id": "GHSA-crit", "database_specific": {"severity": "CRITICAL"}},
            {"id": "GHSA-none"},  # önem yok → medium fallback
        ]
    }
    by_id = {v.id: v.severity for v in parse_osv_response(data)}
    assert by_id["GHSA-high"] == Severity.high
    assert by_id["GHSA-crit"] == Severity.critical
    assert by_id["GHSA-none"] == Severity.medium
