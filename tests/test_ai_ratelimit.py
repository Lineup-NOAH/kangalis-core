"""AI üretim hız-sınırının rota-düzeyi davranışı (/ai/ask üzerinden) — DoS koruması entegrasyonu.

Doğrulananlar:
- Kotaya ulaşınca üretim (generate) ATLANIR ve kullanıcıya görünür rate-limit parçası döner
  (HTMX 2.x 2xx-dışını swap etmediğinden 200 + parça; mevcut AI hata UX'iyle tutarlı).
- Önbellek isabetleri kotaya SAYILMAZ (aynı soru tekrar → üretim yok → sınır tetiklenmez).
- ai_ratelimit_enabled=False → sınırsız (tek-kullanıcılı kurulum etkilenmez).
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.config import settings as app_config
from cybersectool.core import ai_limiter
from cybersectool.core.ai import service as ai_service
from cybersectool.core.models import Role
from cybersectool.core.users import create_user


class FakeRedis:
    """ai_limiter için asenkron Redis alt kümesi (incr/expire/ttl), test boyunca paylaşılır."""

    def __init__(self) -> None:
        self.store: dict[str, int] = {}
        self.ttls: dict[str, int] = {}

    async def incr(self, key: str) -> int:
        self.store[key] = self.store.get(key, 0) + 1
        return self.store[key]

    async def expire(self, key: str, seconds: int) -> None:
        self.ttls[key] = seconds

    async def ttl(self, key: str) -> int:
        return self.ttls.get(key, -1) if key in self.store else -2


async def _login(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    username: str,
    role: Role,
) -> None:
    async with session_factory() as s:
        await create_user(s, username, "pass1234", role=role)
    await client.post(
        "/login", data={"username": username, "password": "pass1234"}, follow_redirects=False
    )


def _arm(monkeypatch: pytest.MonkeyPatch, *, max_req: int, enabled: bool = True) -> list[int]:
    """AI'yı açık say, generate'i sahtele, limiter'a FakeRedis ver; generate çağrı sayacı döner."""
    calls: list[int] = []

    async def fake_gen(config: object, prompt: str, **kwargs: object) -> str:
        calls.append(1)
        return "cevap"

    monkeypatch.setattr("cybersectool.web.routes.ai_available", lambda config: True)
    monkeypatch.setattr(ai_service, "generate", fake_gen)
    monkeypatch.setattr(ai_limiter, "_redis", lambda: _SHARED)
    monkeypatch.setattr(app_config, "ai_ratelimit_enabled", enabled)
    monkeypatch.setattr(app_config, "ai_ratelimit_max", max_req)
    monkeypatch.setattr(app_config, "ai_ratelimit_window_sec", 60)
    return calls


_SHARED = FakeRedis()


@pytest.fixture(autouse=True)
def _fresh_redis() -> None:
    """Her test için paylaşılan FakeRedis'i sıfırla (testler arası sayaç sızmasın)."""
    _SHARED.store.clear()
    _SHARED.ttls.clear()


async def test_blocks_after_quota_and_skips_generation(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """max=2 → 2 üretim geçer, 3. (farklı soru, önbellek-ıskası) ÜRETİLMEZ + rate-limit parçası."""
    calls = _arm(monkeypatch, max_req=2)
    await _login(client, session_factory, "rl_user", Role.analyst)
    r1 = await client.post("/ai/ask", data={"question": "soru bir nasil tararim"})
    r2 = await client.post("/ai/ask", data={"question": "soru iki nasil raporlarim"})
    r3 = await client.post("/ai/ask", data={"question": "soru uc nasil kapsam ayarlarim"})
    assert r1.status_code == r2.status_code == r3.status_code == 200
    assert len(calls) == 2  # 3. üretim ATLANDI (kota)
    assert "istek sınırına" in r3.text  # görünür rate-limit mesajı (200 + parça)


async def test_cache_hit_not_counted(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Aynı soru tekrar → önbellek isabeti → üretim yok → kotaya SAYILMAZ (max=2'yi aşsa bile)."""
    calls = _arm(monkeypatch, max_req=2)
    await _login(client, session_factory, "rl_cache", Role.analyst)
    last = None
    for _ in range(5):
        last = await client.post("/ai/ask", data={"question": "ayni soru tekrar tekrar"})
    assert last is not None and last.status_code == 200
    assert len(calls) == 1  # yalnız ilk istek üretti; 4 isabet sayılmadı
    assert "istek sınırına" not in last.text  # hiç sınırlanmadı


async def test_disabled_is_unlimited(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ai_ratelimit_enabled=False → çok sayıda farklı soru bile sınırsız üretir."""
    calls = _arm(monkeypatch, max_req=1, enabled=False)
    await _login(client, session_factory, "rl_off", Role.analyst)
    for i in range(5):
        r = await client.post("/ai/ask", data={"question": f"farkli soru numara {i}"})
        assert r.status_code == 200
        assert "istek sınırına" not in r.text
    assert len(calls) == 5  # hepsi üretti (sınır kapalı)
