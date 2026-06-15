"""Tarama görevlerinde beklenmeyen hata → 'başarısız' işaretleme + canlı iptal testleri.

bug #6 (network/ping) + YÜKSEK-1 (web/sca takılı 'running' kalmasın) + YÜKSEK-2 (işleme
sırasında 'Durdur' → 'tamamlandı' ile ezilmesin).
"""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.tasks import network_scan, ping_scan, sca_scan, web_scan


async def _boom(*_args: Any, **_kwargs: Any) -> str:
    raise RuntimeError("nmap patladı (parse hatası)")


def test_network_scan_task_marks_failed_on_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """_run istisna fırlatırsa görev çökmek/takılı kalmak yerine taramayı 'başarısız' işaretler."""
    calls: dict[str, Any] = {}

    async def _spy(scan_id: int, target: str, reason: str) -> None:
        calls["scan_id"] = scan_id
        calls["target"] = target
        calls["reason"] = reason

    monkeypatch.setattr(network_scan, "_run", _boom)
    monkeypatch.setattr(network_scan, "_mark_failed", _spy)

    result = network_scan.network_scan_task(123, "10.0.0.0/24", "safe")

    assert result == "failed"
    assert calls["scan_id"] == 123
    assert "nmap patladı" in calls["reason"]


def test_ping_scan_task_marks_failed_on_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """ping_scan görevi de hata durumunda taramayı 'başarısız' işaretler (takılı kalmaz)."""
    calls: dict[str, Any] = {}

    async def _spy(scan_id: int, target: str, reason: str) -> None:
        calls["scan_id"] = scan_id
        calls["reason"] = reason

    monkeypatch.setattr(ping_scan, "_run", _boom)
    monkeypatch.setattr(ping_scan, "_mark_failed", _spy)

    result = ping_scan.ping_scan_task(77, "192.168.1.0/24")

    assert result == "failed"
    assert calls["scan_id"] == 77
    assert "nmap patladı" in calls["reason"]


def test_web_scan_task_marks_failed_on_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """YÜKSEK-1: web taraması da hatada 'başarısız' işaretlenir (takılı 'running' kalmaz)."""
    calls: dict[str, Any] = {}

    async def _spy(scan_id: int, target: str, reason: str) -> None:
        calls["scan_id"] = scan_id
        calls["reason"] = reason

    monkeypatch.setattr(web_scan, "_run", _boom)
    monkeypatch.setattr(web_scan, "_mark_failed", _spy)

    result = web_scan.web_scan_task(55, "http://x.local", "safe")

    assert result == "failed"
    assert calls["scan_id"] == 55
    assert "nmap patladı" in calls["reason"]


def test_sca_scan_task_marks_failed_on_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """YÜKSEK-1: SCA taraması da hata durumunda 'başarısız' işaretlenir (takılı kalmaz)."""
    calls: dict[str, Any] = {}

    async def _spy(scan_id: int, ecosystem: str, reason: str) -> None:
        calls["scan_id"] = scan_id
        calls["reason"] = reason

    monkeypatch.setattr(sca_scan, "_run", _boom)
    monkeypatch.setattr(sca_scan, "_mark_failed", _spy)

    result = sca_scan.sca_scan_task(66, "npm", "{}")

    assert result == "failed"
    assert calls["scan_id"] == 66
    assert "nmap patladı" in calls["reason"]


async def test_scan_cancelled_helper(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """_scan_cancelled taze DB okumasıyla 'cancelled' durumunu doğru saptar (yoksa False)."""
    from cybersectool.core.models import ScanStatus, ScanType
    from cybersectool.core.scans import create_scan, set_scan_status

    async with session_factory() as session:
        scan = await create_scan(session, ScanType.network, "10.0.0.1")
        assert await network_scan._scan_cancelled(session, scan.id) is False
        await set_scan_status(session, scan.id, ScanStatus.cancelled)
        assert await network_scan._scan_cancelled(session, scan.id) is True
        assert await network_scan._scan_cancelled(session, 999_999) is False  # yok → False


async def test_process_results_respects_midway_cancel(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    """YÜKSEK-2: işleme sırasında (apply_risk_scores anında) gelen 'Durdur', sonda koşulsuz
    'tamamlandı' yazımıyla EZİLMEMELİ — tarama 'cancelled' kalmalı."""
    from cybersectool.core.models import ScanMode, ScanStatus, ScanType
    from cybersectool.core.scans import create_scan, get_scan, set_scan_status

    async def _noop_results(*_a: Any, **_k: Any) -> list[Any]:
        return []

    # Ağır işleme adımlarını izole et (DB'siz boş sonuç) — yalnız iptal-ezme davranışını test et.
    monkeypatch.setattr(network_scan, "store_results", _noop_results)
    monkeypatch.setattr(network_scan, "store_nse_findings", _noop_results)

    async with session_factory() as session:
        scan = await create_scan(session, ScanType.network, "10.0.0.1")
        await set_scan_status(session, scan.id, ScanStatus.running)

        async def _cancel_during(sess: Any, cve_ids: Any) -> None:
            # apply_risk_scores tam çalışırken kullanıcı canlı "Durdur" demiş gibi davran.
            await set_scan_status(sess, scan.id, ScanStatus.cancelled)

        monkeypatch.setattr(network_scan, "apply_risk_scores", _cancel_during)

        result = await network_scan._process_results(
            session, scan.id, "10.0.0.1", ScanMode.safe, [], is_vuln=False
        )
        assert result == "cancelled"
        refreshed = await get_scan(session, scan.id)
        await session.refresh(refreshed)
        assert refreshed.status == ScanStatus.cancelled  # 'tamamlandı' ile EZİLMEDİ
