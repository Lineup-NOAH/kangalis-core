"""Kimlikli OS-paket zafiyet kontrolü (dpkg → OSV.dev) — saf yardımcılar + sahte SSH + store."""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.models import Finding, ScanType, Severity
from cybersectool.core.scans import create_scan
from cybersectool.intel.osv import OsvVuln, vuln_from_detail
from cybersectool.scanners.credentialed import (
    HostFacts,
    PackageVuln,
    _scan_os_packages,
    os_package_command,
    osv_ecosystem_for,
    parse_packages,
    store_credentialed,
)


def test_parse_packages() -> None:
    out = parse_packages("openssl 1.1.1n-0+deb11u5\nbash 5.1-2\n\ngarbage\n")
    assert ("openssl", "1.1.1n-0+deb11u5") in out
    assert ("bash", "5.1-2") in out
    assert len(out) == 2  # boş + tek-kelime satır atlanır


def test_osv_ecosystem_for() -> None:
    ubuntu = 'ID=ubuntu\nVERSION_ID="22.04"\nID_LIKE=debian\n'
    debian = 'ID=debian\nVERSION_ID="12"\n'
    assert osv_ecosystem_for(ubuntu) == "Ubuntu:22.04:LTS"
    assert osv_ecosystem_for(debian) == "Debian:12"
    assert osv_ecosystem_for("") is None  # VERSION_ID yok


def test_osv_ecosystem_for_rpm_family() -> None:
    """#138: RPM ailesi desteklenir (RHEL/CentOS → AlmaLinux ABI-uyumlu eşleme)."""
    rocky = 'ID="rocky"\nVERSION_ID="9.3"\nID_LIKE="rhel centos fedora"\n'
    alma = 'ID="almalinux"\nVERSION_ID="8.9"\nID_LIKE="rhel centos fedora"\n'
    rhel = 'ID="rhel"\nVERSION_ID="8.8"\nID_LIKE="fedora"\n'
    centos = 'ID="centos"\nVERSION_ID="8"\n'
    assert osv_ecosystem_for(rocky) == "Rocky Linux:9"
    assert osv_ecosystem_for(alma) == "AlmaLinux:8"
    assert osv_ecosystem_for(rhel) == "AlmaLinux:8"  # ABI-uyumlu yaklaşım
    assert osv_ecosystem_for(centos) == "AlmaLinux:8"


def test_os_package_command() -> None:
    """#138: RPM ailesinde rpm -qa, aksi halde dpkg-query."""
    rhel = 'ID="rhel"\nVERSION_ID="8.8"\nID_LIKE="fedora"\n'
    ubuntu = 'ID=ubuntu\nVERSION_ID="22.04"\nID_LIKE=debian\n'
    assert os_package_command(rhel).startswith("rpm -qa")
    assert os_package_command(ubuntu).startswith("dpkg-query")


def test_osv_ecosystem_for_alpine() -> None:
    """#146 BUG-4b: Alpine → OSV release-dalı ekosistemi (Alpine:v3.19)."""
    alpine = "ID=alpine\nVERSION_ID=3.19.1\n"
    alpine_major = "ID=alpine\nVERSION_ID=3\n"  # minör yoksa yalnız majör
    assert osv_ecosystem_for(alpine) == "Alpine:v3.19"
    assert osv_ecosystem_for(alpine_major) == "Alpine:v3"


def test_os_package_command_alpine_parses() -> None:
    """#146 BUG-4b: Alpine komutu apk db'sinden 'ad sürüm' üretir → parse_packages uyumlu.

    awk komutunun ürettiği biçimi simüle et (``print n, $2`` → "ad sürüm"); parse_packages
    bunu (ve apk'nın ``1.2.4-r2`` sürüm formatını) sorunsuz ayrıştırmalı.
    """
    alpine = "ID=alpine\nVERSION_ID=3.19.1\n"
    cmd = os_package_command(alpine)
    assert "apk" in cmd and "/lib/apk/db/installed" in cmd
    # awk'nın üreteceği çıktı: "ad sürüm" satırları (apk sürümü -rN ekli).
    simulated = "musl 1.2.4-r2\nopenssl 3.1.4-r5\nbusybox 1.36.1-r15\n"
    pkgs = parse_packages(simulated)
    assert ("musl", "1.2.4-r2") in pkgs
    assert ("openssl", "3.1.4-r5") in pkgs
    assert len(pkgs) == 3


def test_vuln_from_detail_severity() -> None:
    detail = {
        "id": "DSA-1234-1",
        "summary": "openssl flaw",
        "aliases": ["CVE-2022-0001", "GHSA-xxx"],
        "database_specific": {"severity": "high"},
    }
    v = vuln_from_detail(detail)
    assert v.id == "DSA-1234-1"
    assert v.cve == "CVE-2022-0001"
    assert v.severity == Severity.high
    # severity yoksa → medium
    assert vuln_from_detail({"id": "X"}).severity == Severity.medium


def test_vuln_from_detail_cve_embedded_in_id() -> None:
    """#146 BUG-4b: Alpine OSV kaydı CVE'yi id'ye gömer (alias YOK) → temiz CVE çıkarılmalı.

    ``id="ALPINE-CVE-2024-58251"``, ``aliases=None`` → cve_id "CVE-2024-58251" olmalı ki CVE
    DB/EPSS/exploit eşleştirmesiyle entegre olsun (yoksa "ALPINE-CVE-..." izole kalırdı).
    """
    alpine = {"id": "ALPINE-CVE-2024-58251", "summary": "busybox flaw"}
    v = vuln_from_detail(alpine)
    assert v.id == "ALPINE-CVE-2024-58251"  # OSV id korunur
    assert v.cve == "CVE-2024-58251"  # temiz CVE çıkarıldı
    # Alias VARSA o öncelikli (mevcut davranış korunur).
    aliased = {"id": "ALPINE-CVE-2024-58251", "aliases": ["CVE-2024-9999"]}
    assert vuln_from_detail(aliased).cve == "CVE-2024-9999"
    # Gömülü/alias CVE yoksa → None.
    assert vuln_from_detail({"id": "DLA-1234-1"}).cve is None


class _FakeResult:
    def __init__(self, stdout: str) -> None:
        self.stdout = stdout


class _FakeConn:
    """Komuttaki alt-dizeye göre çıktı döndüren sahte SSH bağlantısı."""

    def __init__(self, responses: dict[str, str]) -> None:
        self._responses = responses

    async def run(self, command: str, check: bool = False) -> _FakeResult:
        for key, out in self._responses.items():
            if key in command:
                return _FakeResult(out)
        return _FakeResult("")


async def test_scan_os_packages_matches(monkeypatch: pytest.MonkeyPatch) -> None:
    """Desteklenen dağıtım + OSV eşleşmesi → önemden sıralı PackageVuln listesi."""
    conn = _FakeConn(
        {
            "os-release": 'ID=ubuntu\nVERSION_ID="22.04"\n',
            "dpkg-query": "openssl 1.1.1\nbash 5.1\n",
        }
    )

    async def fake_query(
        packages: list[tuple[str, str]], ecosystem: str, **kw: Any
    ) -> dict[tuple[str, str], list[OsvVuln]]:
        assert ecosystem == "Ubuntu:22.04:LTS"
        return {
            ("openssl", "1.1.1"): [
                OsvVuln(id="CVE-A", cve="CVE-2022-0001", severity=Severity.critical)
            ]
        }

    monkeypatch.setattr("cybersectool.scanners.credentialed.query_osv_packages", fake_query)
    vulns = await _scan_os_packages(conn)  # type: ignore[arg-type]
    assert len(vulns) == 1
    assert vulns[0].package == "openssl" and vulns[0].cve == "CVE-2022-0001"
    assert vulns[0].severity == Severity.critical


async def test_scan_os_packages_unsupported_distro() -> None:
    """RPM tabanlı (desteklenmeyen) dağıtımda OSV eşleştirme atlanır (boş)."""
    conn = _FakeConn({"os-release": 'ID="centos"\nVERSION_ID="8"\n'})
    assert await _scan_os_packages(conn) == []  # type: ignore[arg-type]


async def test_store_writes_package_vuln_finding(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Zafiyetli paket → cve_id'li Finding yazılır (yaşam döngüsü + önceliklendirme)."""

    async def noop(session: AsyncSession, cve_ids: list[str]) -> None:
        return None

    monkeypatch.setattr("cybersectool.scanners.credentialed.enrich_cves", noop)
    async with session_factory() as session:
        scan = await create_scan(session, ScanType.credentialed, "10.0.0.5", created_by=None)
        facts = HostFacts(
            os="Ubuntu 22.04",
            kernel="5.15.0",
            package_count=2,
            package_vulns=[
                PackageVuln("openssl", "1.1.1", "CVE-A", "CVE-2022-0001", Severity.high, "flaw")
            ],
        )
        await store_credentialed(session, scan.id, facts, [])
        findings = (await session.execute(select(Finding))).scalars().all()
    pkg = [f for f in findings if f.title.startswith("Zafiyetli paket")]
    assert len(pkg) == 1
    assert pkg[0].cve_id == "CVE-2022-0001"
    assert pkg[0].severity == Severity.high
    assert "openssl" in pkg[0].title
