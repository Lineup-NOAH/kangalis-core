"""DÜŞÜK-öncelik fix testleri (open-redirect, CSV-injection, IPv4+IPv6 sort).

Diğer DÜŞÜK fix'lerin testleri ilgili modül test dosyalarında: sürüm karşılaştırma + Heartbleed
(``test_cpe.py``), banner harf-sonek (``test_vuln.py``), OSV severity (``test_sca.py``).
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.assets import hosts_in_scope, upsert_asset
from cybersectool.web.routes import _csv_safe


def test_csv_safe_neutralizes_formula_injection() -> None:
    """Tehlikeli ön-ekli (=/+/-/@/tab/CR) değer tek-tırnakla nötrlenir; normal değer aynı kalır."""
    assert _csv_safe("=SUM(A1:A9)") == "'=SUM(A1:A9)"
    assert _csv_safe("+1234") == "'+1234"
    assert _csv_safe("-cmd|' /C calc'!A0") == "'-cmd|' /C calc'!A0"
    assert _csv_safe("@import") == "'@import"
    assert _csv_safe("\t=evil") == "'\t=evil"
    assert _csv_safe("scan_start") == "scan_start"  # zararsız → dokunulmaz
    assert _csv_safe("192.168.1.5") == "192.168.1.5"
    assert _csv_safe("") == ""


async def test_hosts_in_scope_sorts_mixed_ipv4_ipv6(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """DÜŞÜK fix: IPv4 + IPv6 karışık host listesi çökmeden sıralanır (v4 önce, içeride sayısal)."""
    async with session_factory() as session:
        await upsert_asset(session, "192.0.2.20", is_up=True)
        await upsert_asset(session, "2001:db8::10", is_up=True)
        await upsert_asset(session, "192.0.2.3", is_up=True)
        # Eskiden bu çağrı 'IPv6Address < IPv4Address' TypeError ile ÇÖKÜYORDU.
        hosts = await hosts_in_scope(session, [])
        ips = [h["ip"] for h in hosts]
    assert ips == ["192.0.2.3", "192.0.2.20", "2001:db8::10"]  # v4 (sayısal) önce, sonra v6
