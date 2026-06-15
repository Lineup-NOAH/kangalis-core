"""Giriş kaba-kuvvet koruması (login_guard) testleri — sahte Redis ile."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core import login_guard
from cybersectool.core.app_settings import save_ratelimit_settings
from cybersectool.core.models import AppSettings, Role
from cybersectool.core.users import create_user


class FakeRedis:
    """login_guard'ın kullandığı asenkron Redis alt kümesi (incr/expire/ttl/set/delete)."""

    def __init__(self) -> None:
        self.store: dict[str, str] = {}
        self.ttls: dict[str, int] = {}

    async def incr(self, key: str) -> int:
        self.store[key] = str(int(self.store.get(key, "0")) + 1)
        return int(self.store[key])

    async def expire(self, key: str, seconds: int) -> None:
        self.ttls[key] = seconds

    async def ttl(self, key: str) -> int:
        if key not in self.store:
            return -2
        return self.ttls.get(key, -1)

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self.store[key] = value
        if ex is not None:
            self.ttls[key] = ex

    async def delete(self, *keys: str) -> None:
        for key in keys:
            self.store.pop(key, None)
            self.ttls.pop(key, None)


def _row(
    *, enabled: bool, max_attempts: int = 3, window: int = 300, lockout: int = 600
) -> AppSettings:
    return AppSettings(
        ratelimit_enabled=enabled,
        ratelimit_max_attempts=max_attempts,
        ratelimit_window_sec=window,
        ratelimit_lockout_sec=lockout,
    )


async def test_lockout_after_threshold(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeRedis()
    monkeypatch.setattr(login_guard, "_redis", lambda: fake)
    row = _row(enabled=True, max_attempts=3, lockout=600)
    # İlk iki başarısızlık kilitlemez.
    assert await login_guard.record_login_failure(row, "Alice") == 0
    assert await login_guard.record_login_failure(row, "alice") == 0
    assert await login_guard.login_lockout_remaining(row, "alice") == 0
    # Üçüncü başarısızlık hesabı kilitler (kullanıcı adı normalize: büyük/küçük fark etmez).
    assert await login_guard.record_login_failure(row, "ALICE") == 600
    assert await login_guard.login_lockout_remaining(row, "alice") == 600
    # Başarılı giriş sonrası temizlik kilidi kaldırır.
    await login_guard.clear_login_failures("alice")
    assert await login_guard.login_lockout_remaining(row, "alice") == 0


async def test_disabled_never_locks(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeRedis()
    monkeypatch.setattr(login_guard, "_redis", lambda: fake)
    row = _row(enabled=False, max_attempts=1)
    # Koruma kapalı → sayma/kilit yok, Redis'e dokunmaz.
    assert await login_guard.record_login_failure(row, "bob") == 0
    assert await login_guard.login_lockout_remaining(row, "bob") == 0
    assert fake.store == {}


async def test_redis_failure_fails_open(monkeypatch: pytest.MonkeyPatch) -> None:
    class BoomRedis:
        async def incr(self, key: str) -> int:
            raise ConnectionError("redis down")

        async def ttl(self, key: str) -> int:
            raise ConnectionError("redis down")

    monkeypatch.setattr(login_guard, "_redis", lambda: BoomRedis())
    row = _row(enabled=True, max_attempts=1)
    # Redis hatası → fail-open (kilit yok, istisna sızmaz).
    assert await login_guard.record_login_failure(row, "carol") == 0
    assert await login_guard.login_lockout_remaining(row, "carol") == 0


async def test_web_login_lockout_blocks_correct_password(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeRedis()
    monkeypatch.setattr(login_guard, "_redis", lambda: fake)
    async with session_factory() as session:
        await create_user(session, "victim", "rightpass", role=Role.viewer)
        await save_ratelimit_settings(
            session, enabled=True, max_attempts=2, window_sec=300, lockout_sec=600
        )
    # 1. yanlış deneme → 401 (henüz kilit yok)
    r1 = await client.post(
        "/login", data={"username": "victim", "password": "wrong"}, follow_redirects=False
    )
    assert r1.status_code == 401
    # 2. yanlış deneme → eşik (2) aşıldı → 429 kilit
    r2 = await client.post(
        "/login", data={"username": "victim", "password": "wrong"}, follow_redirects=False
    )
    assert r2.status_code == 429
    # Kilitliyken DOĞRU parola bile reddedilir.
    r3 = await client.post(
        "/login", data={"username": "victim", "password": "rightpass"}, follow_redirects=False
    )
    assert r3.status_code == 429
