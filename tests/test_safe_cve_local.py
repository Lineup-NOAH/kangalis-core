"""SAFE-CVE-LOCAL: güvenli CVE taraması yalnız yerel bankayı kullanır (canlı NVD yok).

CVE/CPE bilgi bankası ile Exploit/Payload DB ayrıldıktan sonra güvenli mod ağsızdır;
canlı NVD genişletmesi sadece zafiyet (derin) modunda devreye girer.
"""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.models import Service
from cybersectool.tasks import network_scan as ns


async def test_safe_mode_local_only(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Güvenli mod (is_vuln=False): yalnız offline (yerel) çağrılır; canlı NVD çağrılmaz."""
    calls = {"offline": 0, "online": 0}

    async def fake_offline(session: AsyncSession, scan_id: int, service: Service) -> list[str]:
        calls["offline"] += 1
        return ["CVE-LOCAL-1"]

    async def fake_online(session: AsyncSession, scan_id: int, service: Service) -> list[str]:
        calls["online"] += 1
        return ["CVE-ONLINE-1"]

    monkeypatch.setattr(ns, "match_service_cves_offline", fake_offline)
    monkeypatch.setattr(ns, "match_service_cves", fake_online)

    async with session_factory() as session:
        result = await ns._match_cves_for_service(
            session, 1, Service(asset_id=1, port=22), is_vuln=False
        )

    assert result == ["CVE-LOCAL-1"]
    assert calls["offline"] == 1
    assert calls["online"] == 0  # güvenli mod: ağsız


async def test_vuln_mode_local_plus_online(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Zafiyet (derin) mod: yerel + canlı NVD genişletmesi birleşir."""
    calls = {"offline": 0, "online": 0}

    async def fake_offline(session: AsyncSession, scan_id: int, service: Service) -> list[str]:
        calls["offline"] += 1
        return ["CVE-LOCAL-1"]

    async def fake_online(session: AsyncSession, scan_id: int, service: Service) -> list[str]:
        calls["online"] += 1
        return ["CVE-ONLINE-1"]

    monkeypatch.setattr(ns, "match_service_cves_offline", fake_offline)
    monkeypatch.setattr(ns, "match_service_cves", fake_online)

    async with session_factory() as session:
        result = await ns._match_cves_for_service(
            session, 1, Service(asset_id=1, port=22), is_vuln=True
        )

    assert result == ["CVE-LOCAL-1", "CVE-ONLINE-1"]
    assert calls["offline"] == 1
    assert calls["online"] == 1  # zafiyet modu: online derinleştir


async def test_vuln_mode_online_failure_keeps_local(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Zafiyet modunda canlı NVD hata verirse yerel sonuçlar korunur (tarama çökmez)."""

    async def fake_offline(session: AsyncSession, scan_id: int, service: Service) -> list[str]:
        return ["CVE-LOCAL-1"]

    async def fake_online_boom(session: AsyncSession, scan_id: int, service: Service) -> list[str]:
        raise RuntimeError("NVD erişilemedi")

    monkeypatch.setattr(ns, "match_service_cves_offline", fake_offline)
    monkeypatch.setattr(ns, "match_service_cves", fake_online_boom)

    async with session_factory() as session:
        result = await ns._match_cves_for_service(
            session, 1, Service(asset_id=1, port=22), is_vuln=True
        )

    assert result == ["CVE-LOCAL-1"]  # online patladı → yerel yine döner
