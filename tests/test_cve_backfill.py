"""NVD geçmiş-yükleme (backfill) ilerleme/iptal durumu + pencere bölme testleri — sahte Redis."""

from __future__ import annotations

import pytest

from cybersectool.core import cve_backfill as bf
from cybersectool.intel.nvd import NVD_MAX_WINDOW_DAYS, backfill_windows


class FakeRedis:
    """cve_backfill'in kullandığı async Redis hash alt kümesi (hset/hget/hgetall/delete/expire)."""

    def __init__(self) -> None:
        self.h: dict[str, dict[str, str]] = {}
        self.kv: dict[str, str] = {}
        self.ttls: dict[str, int] = {}

    async def delete(self, *keys: str) -> None:
        for key in keys:
            self.h.pop(key, None)
            self.kv.pop(key, None)
            self.ttls.pop(key, None)

    async def set(
        self, key: str, value: str, *, nx: bool = False, ex: int | None = None
    ) -> bool | None:
        if nx and key in self.kv:
            return None  # NX: zaten var → alınamaz
        self.kv[key] = value
        if ex is not None:
            self.ttls[key] = ex
        return True

    async def hset(
        self,
        key: str,
        field: str | None = None,
        value: str | None = None,
        *,
        mapping: dict[str, str] | None = None,
    ) -> None:
        slot = self.h.setdefault(key, {})
        if mapping:
            for k, v in mapping.items():
                slot[k] = str(v)
        if field is not None:
            slot[field] = str(value)

    async def hget(self, key: str, field: str) -> str | None:
        return self.h.get(key, {}).get(field)

    async def hgetall(self, key: str) -> dict[str, str]:
        return dict(self.h.get(key, {}))

    async def expire(self, key: str, seconds: int) -> None:
        self.ttls[key] = seconds


async def test_state_lifecycle(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeRedis()
    monkeypatch.setattr(bf, "_redis", lambda: fake)
    # Başlangıçta durum yok.
    assert await bf.state() is None

    await bf.begin(windows_total=10, years=2)
    st = await bf.state()
    assert st is not None
    assert st["status"] == "running"
    assert st["percent"] == 0
    assert await bf.is_active() is True

    await bf.update(windows_done=5, cves=1234, cpe_total=2000, current="2024-01-01 – 2024-04-30")
    st = await bf.state()
    assert st is not None
    assert st["percent"] == 50  # 5/10
    assert st["cves"] == "1234"
    assert st["current"] == "2024-01-01 – 2024-04-30"

    await bf.finish(status="done", cves=4321, cpe_total=8000)
    st = await bf.state()
    assert st is not None
    assert st["status"] == "done"
    assert st["cves"] == "4321"
    assert await bf.is_active() is False


async def test_percent_caps_and_queued(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeRedis()
    monkeypatch.setattr(bf, "_redis", lambda: fake)
    # queued: pencere sayısı bilinmiyor (0) → percent 0, aktif sayılır.
    await bf.mark_queued(years=5)
    st = await bf.state()
    assert st is not None
    assert st["status"] == "queued"
    assert st["percent"] == 0
    assert await bf.is_active() is True

    # windows_done > total olsa bile percent 100'ü aşmaz.
    await bf.begin(windows_total=4, years=1)
    await bf.update(windows_done=9, cves=10, cpe_total=10, current="x")
    st = await bf.state()
    assert st is not None
    assert st["percent"] == 100


async def test_cancel_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeRedis()
    monkeypatch.setattr(bf, "_redis", lambda: fake)
    # Aktif değilken iptal istenirse işaretlenmez.
    assert await bf.request_cancel() is False

    await bf.begin(windows_total=3, years=1)
    assert await bf.is_cancelled() is False
    assert await bf.request_cancel() is True
    assert await bf.is_cancelled() is True

    # Terminal duruma geçince yeni iptal isteği işaretlenmez.
    await bf.finish(status="cancelled", cves=0, cpe_total=0)
    assert await bf.request_cancel() is False


async def test_single_run_lock(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeRedis()
    monkeypatch.setattr(bf, "_redis", lambda: fake)
    # İlk worker kilidi alır; ikinci (çift-dispatch) alamaz → erken çıkar.
    assert await bf.acquire() is True
    assert await bf.acquire() is False
    # Bırakınca yeniden alınabilir.
    await bf.release()
    assert await bf.acquire() is True


async def test_lock_fails_open_without_redis(monkeypatch: pytest.MonkeyPatch) -> None:
    class BoomRedis:
        async def set(self, *a: object, **k: object) -> bool:
            raise ConnectionError("redis down")

    monkeypatch.setattr(bf, "_redis", lambda: BoomRedis())
    # Redis yoksa kilit alınamaz AMA çekirdek iş koşsun diye fail-OPEN (True).
    assert await bf.acquire() is True


async def test_queued_cancel_preserved_by_begin(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeRedis()
    monkeypatch.setattr(bf, "_redis", lambda: fake)
    # Senaryo: route mark_queued → kullanıcı queued sırasında İPTAL → worker begin().
    await bf.mark_queued(years=2)
    assert await bf.request_cancel() is True  # queued sırasında iptal
    await bf.begin(windows_total=5, years=2)  # worker başlar
    # begin() iptal bayrağını EZMEMELİ; ilk pencere yoklamasında durmalı.
    assert await bf.is_cancelled() is True


async def test_redis_failure_is_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    class BoomRedis:
        async def hgetall(self, key: str) -> dict[str, str]:
            raise ConnectionError("redis down")

        async def hget(self, key: str, field: str) -> str | None:
            raise ConnectionError("redis down")

    monkeypatch.setattr(bf, "_redis", lambda: BoomRedis())
    # Redis hatası → fail-safe: durum None, aktif değil, iptal değil (istisna sızmaz).
    assert await bf.state() is None
    assert await bf.is_active() is False
    assert await bf.is_cancelled() is False
    assert await bf.request_cancel() is False


def test_backfill_windows_newest_first() -> None:
    windows = backfill_windows(400)
    # 400 gün > 120 → en az 4 pencere (120+120+120+40).
    assert len(windows) >= 4
    # Her pencere span'ı ≤ 120 gün.
    for start, end in windows:
        assert (end - start).days <= NVD_MAX_WINDOW_DAYS
    # En yeni pencere önce: ilk pencerenin bitişi, son pencerenin bitişinden sonra.
    assert windows[0][1] > windows[-1][1]
    # Pencereler bitişik + azalan sırada (bir sonrakinin bitişi öncekinin başlangıcı).
    for newer, older in zip(windows, windows[1:], strict=False):
        assert older[1] == newer[0]


def test_backfill_windows_small_range() -> None:
    # 30 gün < 120 → tek pencere.
    windows = backfill_windows(30)
    assert len(windows) == 1
    assert (windows[0][1] - windows[0][0]).days <= 30
