"""AI üretim hız-sınırı (ai_limiter) birim testleri — kullanıcı-bazlı Redis sayaçlı DoS koruması.

login_guard testleriyle aynı desen: gerçek Redis yerine FakeRedis enjekte edilir; sınır
ayarları ``app_config`` üzerinde monkeypatch'lenir. Fail-open + pencere + kullanıcı izolasyonu
doğrulanır.
"""

from __future__ import annotations

import pytest

from cybersectool.config import settings as app_config
from cybersectool.core import ai_limiter


class FakeRedis:
    """ai_limiter'ın kullandığı asenkron Redis alt kümesi (incr/expire/ttl)."""

    def __init__(self) -> None:
        self.store: dict[str, int] = {}
        self.ttls: dict[str, int] = {}
        self.expire_calls = 0

    async def incr(self, key: str) -> int:
        self.store[key] = self.store.get(key, 0) + 1
        return self.store[key]

    async def expire(self, key: str, seconds: int) -> None:
        self.expire_calls += 1
        self.ttls[key] = seconds

    async def ttl(self, key: str) -> int:
        if key not in self.store:
            return -2
        return self.ttls.get(key, -1)


def _enable(monkeypatch: pytest.MonkeyPatch, *, max_req: int = 3, window: int = 60) -> None:
    monkeypatch.setattr(app_config, "ai_ratelimit_enabled", True)
    monkeypatch.setattr(app_config, "ai_ratelimit_max", max_req)
    monkeypatch.setattr(app_config, "ai_ratelimit_window_sec", window)


async def test_disabled_never_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    """ai_ratelimit_enabled=False → Redis'e bile dokunmadan her zaman 0 (sınırsız)."""
    monkeypatch.setattr(app_config, "ai_ratelimit_enabled", False)

    def _boom() -> FakeRedis:  # çağrılırsa test patlasın (kapalıyken Redis'e dokunulmamalı)
        raise AssertionError("kapalıyken _redis çağrılmamalı")

    monkeypatch.setattr(ai_limiter, "_redis", _boom)
    for _ in range(50):
        assert await ai_limiter.ai_rate_limited(7) == 0


async def test_under_limit_allows(monkeypatch: pytest.MonkeyPatch) -> None:
    """max=3 → ilk 3 istek 0 (izin)."""
    _enable(monkeypatch, max_req=3)
    fake = FakeRedis()
    monkeypatch.setattr(ai_limiter, "_redis", lambda: fake)
    assert await ai_limiter.ai_rate_limited(1) == 0
    assert await ai_limiter.ai_rate_limited(1) == 0
    assert await ai_limiter.ai_rate_limited(1) == 0


async def test_over_limit_returns_remaining_seconds(monkeypatch: pytest.MonkeyPatch) -> None:
    """max=3, window=60 → 4. istek kalan pencere saniyesini (>0) döner; ilk istek TTL'i kurar."""
    _enable(monkeypatch, max_req=3, window=60)
    fake = FakeRedis()
    monkeypatch.setattr(ai_limiter, "_redis", lambda: fake)
    for _ in range(3):
        assert await ai_limiter.ai_rate_limited(1) == 0
    wait = await ai_limiter.ai_rate_limited(1)
    assert wait == 60  # FakeRedis ttl = ilk istekte kurulan pencere
    # expire YALNIZ ilk istekte (count==1) çağrıldı → pencere kaymıyor (sliding değil). TTL'in
    # 60 olması bunu kanıtlamaz (expire koşulsuz yazar); çağrı sayısı yük-taşıyan asserttir.
    assert fake.expire_calls == 1


async def test_per_user_isolation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sayaç kullanıcı başına ayrı: bir kullanıcının kotası diğerini etkilemez."""
    _enable(monkeypatch, max_req=2)
    fake = FakeRedis()
    monkeypatch.setattr(ai_limiter, "_redis", lambda: fake)
    assert await ai_limiter.ai_rate_limited(1) == 0
    assert await ai_limiter.ai_rate_limited(1) == 0
    assert await ai_limiter.ai_rate_limited(1) > 0  # kullanıcı 1 doldu
    assert await ai_limiter.ai_rate_limited(2) == 0  # kullanıcı 2 hâlâ taze


async def test_fail_open_on_redis_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Redis hatası → 0 (fail-open: bir Redis kesintisi AI'yı tüm kullanıcılara kapatmamalı)."""
    _enable(monkeypatch, max_req=1)

    class BoomRedis:
        async def incr(self, key: str) -> int:
            raise OSError("redis down")

    monkeypatch.setattr(ai_limiter, "_redis", lambda: BoomRedis())
    assert await ai_limiter.ai_rate_limited(1) == 0
    assert await ai_limiter.ai_rate_limited(1) == 0


async def test_self_heal_when_initial_expire_lost(monkeypatch: pytest.MonkeyPatch) -> None:
    """incr başarılı ama ilk expire patlarsa (TTL'siz anahtar) → sınır aşımında pencere YENİDEN
    kurulur (kalıcı kilit yok). TTL'in (re-)kurulması, healed'i kalıcı-stuck'tan ayıran kanıttır:
    ikisi de ``window`` döndürür, ama yalnız healed'de anahtarın TTL'i olur → eninde sıfırlar.
    """
    _enable(monkeypatch, max_req=2, window=60)

    class LeakyRedis(FakeRedis):
        """İlk expire'ı düşürür (count==1'de bölük Redis hatası), sonrakiler başarılı."""

        def __init__(self) -> None:
            super().__init__()
            self._fail_next_expire = True

        async def expire(self, key: str, seconds: int) -> None:
            if self._fail_next_expire:
                self._fail_next_expire = False
                raise OSError("expire düştü")  # count==1 TTL'i kurulamaz → sızıntı koşulu
            await super().expire(key, seconds)

    leaky = LeakyRedis()
    monkeypatch.setattr(ai_limiter, "_redis", lambda: leaky)
    assert await ai_limiter.ai_rate_limited(1) == 0  # count=1: expire patlar, TTL yok
    assert await ai_limiter.ai_rate_limited(1) == 0  # count=2: ≤max
    wait = await ai_limiter.ai_rate_limited(1)  # count=3: >max → self-heal re-arm
    assert wait == 60
    assert leaky.ttls.get("kg:ai:req:1") == 60  # TTL artık kuruldu → kalıcı kilit DEĞİL
