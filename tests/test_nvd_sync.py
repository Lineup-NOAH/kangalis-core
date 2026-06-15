"""NVD senkron pencere-bölme + sayfalama + bütçe (CVE kapsam genişletme) testleri."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from cybersectool.intel import nvd


def test_date_windows_within_limit() -> None:
    """<=120 günlük aralık tek pencere kalır."""
    end = datetime(2026, 6, 9, tzinfo=UTC)
    start = end - timedelta(days=90)
    windows = nvd._date_windows(start, end)
    assert windows == [(start, end)]


def test_date_windows_splits_into_120_day_chunks() -> None:
    """300 günlük aralık → 120 + 120 + 60 ardışık pencere (sınır aşılmaz)."""
    end = datetime(2026, 6, 9, tzinfo=UTC)
    start = end - timedelta(days=300)
    windows = nvd._date_windows(start, end)
    assert len(windows) == 3
    # ardışık ve boşluksuz
    assert windows[0][0] == start
    assert windows[0][1] == windows[1][0]
    assert windows[1][1] == windows[2][0]
    assert windows[-1][1] == end
    # her pencere <= 120 gün
    for ws, we in windows:
        assert (we - ws) <= timedelta(days=nvd.NVD_MAX_WINDOW_DAYS)
    # son pencere 60 gün
    assert windows[-1][1] - windows[-1][0] == timedelta(days=60)


def test_date_windows_exact_boundary() -> None:
    """Tam 240 gün → tam 2 pencere (artık pencere yok)."""
    end = datetime(2026, 6, 9, tzinfo=UTC)
    start = end - timedelta(days=240)
    assert len(nvd._date_windows(start, end)) == 2


def test_default_max_pages_scales_with_days() -> None:
    ppw = nvd.NVD_PAGES_PER_WINDOW
    assert nvd._default_max_pages(120) == ppw  # 1 pencere
    assert nvd._default_max_pages(121) == 2 * ppw  # 2 pencere
    assert nvd._default_max_pages(360) == 3 * ppw  # 3 pencere
    assert nvd._default_max_pages(0) == ppw  # en az 1 pencere


def test_request_delay_depends_on_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(nvd.settings, "nvd_api_key", "")
    assert nvd._request_delay() == 6.0
    # Açıkça geçilen anahtar (DB) hızlı rate-limit'i etkinleştirir.
    assert nvd._request_delay("db-key") == 0.6
    assert nvd._headers("db-key") == {"apiKey": "db-key"}
    # Env fallback: parametre yoksa config'ten okunur.
    monkeypatch.setattr(nvd.settings, "nvd_api_key", "env-key")
    assert nvd._request_delay() == 0.6
    assert nvd._headers() == {"apiKey": "env-key"}
    assert nvd._headers("") == {"apiKey": "env-key"}  # boş param → env fallback


async def test_fetch_nvd_recent_forwards_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """DB'den gelen api_key, _fetch_nvd_pages'e iletilir."""
    captured: dict[str, object] = {}

    async def fake_pages(days: int, max_pages: int, *, api_key: str | None = None) -> list[Any]:
        captured["api_key"] = api_key
        return []

    monkeypatch.setattr(nvd, "_fetch_nvd_pages", fake_pages)
    await nvd.fetch_nvd_recent(days=90, api_key="db-key")
    assert captured["api_key"] == "db-key"


def _patch_transport(monkeypatch: pytest.MonkeyPatch, handler: Any) -> None:
    """httpx.AsyncClient'i MockTransport'lu istemciyle değiştirir + sleep'i susturur."""
    transport = httpx.MockTransport(handler)
    real_client = httpx.AsyncClient

    def factory(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs.pop("transport", None)
        return real_client(*args, transport=transport, **kwargs)

    monkeypatch.setattr(nvd.httpx, "AsyncClient", factory)

    async def _no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(nvd.asyncio, "sleep", _no_sleep)


async def test_fetch_nvd_pages_iterates_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    """300 gün → 3 pencere → 3 ayrı istek (her biri farklı pubStartDate)."""
    seen_starts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        params = dict(request.url.params)
        seen_starts.append(params["pubStartDate"])
        start_index = int(params["startIndex"])
        body = {
            "vulnerabilities": [{"cve": {"id": f"CVE-2026-{start_index}"}}],
            "totalResults": 1,
        }
        return httpx.Response(200, json=body)

    _patch_transport(monkeypatch, handler)
    pages = await nvd._fetch_nvd_pages(days=300, max_pages=99)
    assert len(pages) == 3  # her pencereden bir sayfa
    assert len(set(seen_starts)) == 3  # üç AYRI pencere sorgulandı


async def test_fetch_nvd_pages_last_mod(monkeypatch: pytest.MonkeyPatch) -> None:
    """#144: last_mod=True → pubStartDate yerine lastModStartDate ile sorgular."""
    keys: set[str] = set()

    def handler(request: httpx.Request) -> httpx.Response:
        keys.update(request.url.params.keys())
        return httpx.Response(
            200, json={"vulnerabilities": [{"cve": {"id": "CVE-X"}}], "totalResults": 1}
        )

    _patch_transport(monkeypatch, handler)
    await nvd._fetch_nvd_pages(days=30, max_pages=1, last_mod=True)
    assert "lastModStartDate" in keys
    assert "pubStartDate" not in keys


async def test_fetch_nvd_pages_respects_total_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    """max_pages tüm pencereler genelinde TOPLAM istek bütçesidir."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"vulnerabilities": [{"cve": {"id": "CVE-X"}}], "totalResults": 1}
        )

    _patch_transport(monkeypatch, handler)
    pages = await nvd._fetch_nvd_pages(days=300, max_pages=2)  # 3 pencere ama bütçe 2
    assert len(pages) == 2


async def test_fetch_nvd_pages_paginates_within_window(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tek pencere içinde totalResults aşılana dek startIndex ile sayfalanır."""

    def handler(request: httpx.Request) -> httpx.Response:
        start_index = int(dict(request.url.params)["startIndex"])
        remaining = 3 - start_index
        count = min(2, max(remaining, 0))
        vulns = [{"cve": {"id": f"CVE-{start_index + i}"}} for i in range(count)]
        return httpx.Response(200, json={"vulnerabilities": vulns, "totalResults": 3})

    _patch_transport(monkeypatch, handler)
    pages = await nvd._fetch_nvd_pages(days=30, max_pages=10)  # tek pencere
    assert len(pages) == 2  # 2 + 1 = 3 → iki sayfa


async def test_fetch_nvd_pages_returns_partial_on_http_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """İstek hatasında o ana dek toplanan sayfalar kısmî döner (çökmeden)."""
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(
                200,
                json={
                    "vulnerabilities": [{"cve": {"id": "CVE-A"}}, {"cve": {"id": "CVE-B"}}],
                    "totalResults": 99,
                },
            )
        return httpx.Response(500, json={})

    _patch_transport(monkeypatch, handler)
    pages = await nvd._fetch_nvd_pages(days=30, max_pages=5)
    assert len(pages) == 1  # ilk sayfa toplandı, ikinci istek 500 → kısmî döner


async def test_fetch_nvd_recent_uses_configured_days(monkeypatch: pytest.MonkeyPatch) -> None:
    """days verilmezse settings.nvd_sync_days + türetilmiş max_pages kullanılır."""
    captured: dict[str, int] = {}

    async def fake_pages(
        days: int, max_pages: int, *, api_key: str | None = None, last_mod: bool = False
    ) -> list[dict[str, Any]]:
        captured["days"] = days
        captured["max_pages"] = max_pages
        return []

    monkeypatch.setattr(nvd, "_fetch_nvd_pages", fake_pages)
    monkeypatch.setattr(nvd.settings, "nvd_sync_days", 365)
    await nvd.fetch_nvd_recent()
    assert captured["days"] == 365
    assert captured["max_pages"] == nvd._default_max_pages(365)


async def test_fetch_nvd_cve_data_explicit_days_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """Açıkça verilen days/max_pages ayarı geçersiz kılar."""
    captured: dict[str, int] = {}

    async def fake_pages(
        days: int, max_pages: int, *, api_key: str | None = None, last_mod: bool = False
    ) -> list[dict[str, Any]]:
        captured["days"] = days
        captured["max_pages"] = max_pages
        return []

    monkeypatch.setattr(nvd, "_fetch_nvd_pages", fake_pages)
    monkeypatch.setattr(nvd.settings, "nvd_sync_days", 365)
    await nvd.fetch_nvd_cve_data(days=30, max_pages=4)
    assert captured["days"] == 30
    assert captured["max_pages"] == 4
