"""Risk önceliklendirme skoru + severity dağılımı testleri."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.assets import upsert_asset
from cybersectool.core.findings import count_by_severity, create_finding
from cybersectool.core.models import ScanType, Severity
from cybersectool.core.risk import (
    compute_priority,
    exploit_level_from_hit,
    is_urgent,
)
from cybersectool.core.scans import create_scan


def test_compute_priority() -> None:
    # CVSS tabanı
    assert compute_priority(5.0, None, kev=False) == 5.0
    # EPSS +2'ye kadar
    assert compute_priority(5.0, 0.5, kev=False) == 6.0
    # KEV +3
    assert compute_priority(5.0, None, kev=True) == 8.0
    # 10 ile sınırlı
    assert compute_priority(9.8, 0.94, kev=True) == 10.0
    # CVSS yok
    assert compute_priority(None, None, kev=False) == 0.0


def test_compute_priority_exploit_signal() -> None:
    """VI-1: exploit sinyali skora girer (silahlandırılmış +1.5, PoC +0.5)."""
    # PoC (level 1) → +0.5
    assert compute_priority(5.0, None, kev=False, exploit_level=1) == 5.5
    # Silahlandırılmış/Metasploit (level 2) → +1.5
    assert compute_priority(5.0, None, kev=False, exploit_level=2) == 6.5
    # Level 0 → değişiklik yok (geriye uyumlu)
    assert compute_priority(5.0, None, kev=False, exploit_level=0) == 5.0
    # Exploit de 10 ile sınırlı
    assert compute_priority(9.5, None, kev=True, exploit_level=2) == 10.0


def test_compute_priority_severity_base_when_no_cvss() -> None:
    """#136: CVSS yokken severity etiketinden taban türetilir (taban 0 ile hafife alma yok)."""
    # CVSS yok ama severity var → severity tabanı
    assert compute_priority(None, None, kev=False, severity="critical") == 9.0
    assert compute_priority(None, None, kev=False, severity="high") == 7.0
    assert compute_priority(None, None, kev=False, severity="medium") == 5.0
    # CVSS varsa severity yok sayılır (CVSS önceliklidir)
    assert compute_priority(4.0, None, kev=False, severity="critical") == 4.0
    # Bilinmeyen/eksik severity → 0
    assert compute_priority(None, None, kev=False, severity=None) == 0.0


def test_compute_priority_kev_floor() -> None:
    """#136: KEV (aktif sömürü) → CVSS yoksa bile en az 7.0 (hafife alınmaz)."""
    # KEV + CVSS yok + severity yok → taban 0 + 3 = 3, ama KEV tabanı 7.0
    assert compute_priority(None, None, kev=True, severity=None) == 7.0
    # KEV + düşük CVSS → 2+3=5 ama floor 7.0
    assert compute_priority(2.0, None, kev=True) == 7.0
    # KEV + critical severity (CVSS yok) → 9+3=12 → 10
    assert compute_priority(None, None, kev=True, severity="critical") == 10.0


def test_exploit_level_from_hit() -> None:
    assert exploit_level_from_hit(0, False) == 0
    assert exploit_level_from_hit(3, False) == 1  # PoC var ama MSF yok
    assert exploit_level_from_hit(1, True) == 2  # Metasploit modülü
    assert exploit_level_from_hit(0, True) == 0  # sayı 0 → yok say


def test_is_urgent() -> None:
    """Acil kovası: KEV VEYA EPSS≥0.5 VEYA silahlandırılmış."""
    assert is_urgent(kev=True, epss=None, weaponized=False) is True
    assert is_urgent(kev=False, epss=0.5, weaponized=False) is True
    assert is_urgent(kev=False, epss=0.49, weaponized=False) is False
    assert is_urgent(kev=False, epss=None, weaponized=True) is True
    assert is_urgent(kev=False, epss=0.1, weaponized=False) is False


async def test_count_by_severity(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        asset = await upsert_asset(session, "10.0.0.1")
        scan = await create_scan(session, ScanType.network, "x")
        await create_finding(session, scan.id, "a", severity=Severity.critical, asset_id=asset.id)
        await create_finding(session, scan.id, "b", severity=Severity.critical, asset_id=asset.id)
        await create_finding(session, scan.id, "c", severity=Severity.high, asset_id=asset.id)
        counts = await count_by_severity(session)
        assert counts["critical"] == 2
        assert counts["high"] == 1
