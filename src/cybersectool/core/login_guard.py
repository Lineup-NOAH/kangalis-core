"""Giriş kaba-kuvvet koruması (rate-limit + lockout) — Redis sayaçlı.

``app_settings`` tablosundaki ``ratelimit_*`` değerlerine göre çalışır. Belirli bir
zaman penceresinde eşik kadar başarısız giriş olursa hesap (kullanıcı adı) geçici
olarak kilitlenir; kilitliyken doğru parola bile reddedilir.

Tasarım notları:
- **Hesap bazlı kilit**: anahtar kullanıcı adıdır; cevap kullanıcının var olup
  olmadığını sızdırmaz (mevcut "kullanıcı adı veya parola hatalı" davranışıyla uyumlu).
- **Fail-open**: Redis erişilemezse koruma devre dışı kalır ve girişe izin verilir —
  bir Redis kesintisi tüm kullanıcıları kilitlememelidir (kullanılabilirlik > katılık).
- Sayaç penceresi ``ratelimit_window_sec`` ile (ilk başarısızlıkta) TTL'lenir; kilit
  ``ratelimit_lockout_sec`` boyunca tutulur.
"""

from __future__ import annotations

import contextlib

import redis.asyncio as aioredis

from cybersectool.config import settings as app_config
from cybersectool.core.models import AppSettings

_FAIL_PREFIX = "kg:login:fail:"
_LOCK_PREFIX = "kg:login:lock:"

_client: aioredis.Redis | None = None


def _redis() -> aioredis.Redis:
    """Süreç-ömrü boyunca tek async Redis istemcisi (lazy)."""
    global _client
    if _client is None:
        # redis.asyncio.from_url tip-işaretsiz (no-untyped-call); dönüş yine de Redis tipli.
        _client = aioredis.from_url(  # type: ignore[no-untyped-call]
            app_config.redis_url, decode_responses=True
        )
    return _client


def _norm(username: str) -> str:
    """Kullanıcı adını kilit anahtarı için normalize eder (küçük harf, kırpılmış)."""
    return username.strip().lower()[:120]


async def login_lockout_remaining(row: AppSettings, username: str) -> int:
    """Hesap kilitliyse kalan saniye, değilse 0.

    Koruma kapalıysa ya da Redis erişilemezse 0 (fail-open) döner.
    """
    if not row.ratelimit_enabled:
        return 0
    key = _LOCK_PREFIX + _norm(username)
    with contextlib.suppress(Exception):
        ttl = await _redis().ttl(key)
        if ttl and ttl > 0:
            return int(ttl)
    return 0


async def record_login_failure(row: AppSettings, username: str) -> int:
    """Başarısız denemeyi sayar; eşik aşılırsa hesabı kilitler.

    Kilitlendiyse kilit süresini (saniye), aksi halde 0 döner.
    """
    if not row.ratelimit_enabled:
        return 0
    uname = _norm(username)
    fail_key = _FAIL_PREFIX + uname
    lock_key = _LOCK_PREFIX + uname
    with contextlib.suppress(Exception):
        client = _redis()
        count = await client.incr(fail_key)
        if count == 1:
            await client.expire(fail_key, row.ratelimit_window_sec)
        if count >= row.ratelimit_max_attempts:
            await client.set(lock_key, "1", ex=row.ratelimit_lockout_sec)
            await client.delete(fail_key)
            return row.ratelimit_lockout_sec
    return 0


async def clear_login_failures(username: str) -> None:
    """Başarılı giriş sonrası sayaç + kilidi temizler (sessizce başarısız olabilir)."""
    uname = _norm(username)
    with contextlib.suppress(Exception):
        client = _redis()
        await client.delete(_FAIL_PREFIX + uname, _LOCK_PREFIX + uname)
