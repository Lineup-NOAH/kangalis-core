"""E-posta OTP (tek-kullanımlık kod) — Redis'te hash'li, TTL'li saklanır.

Hem kayıt onayı hem login ikinci adımı için kullanılır. Kod düz metin değil sha256
**hash**'iyle saklanır (Redis sızıntısında kod açığa çıkmaz) ve doğrulanınca **silinir**
(tekrar kullanım engellenir). Süre TTL ile, kaba-kuvvet ise login kilidiyle (S1) sınırlı.

Fail-closed: Redis erişilemezse doğrulama False döner (MFA bypass edilmez).
"""

from __future__ import annotations

import contextlib
import hashlib
import secrets

import redis.asyncio as aioredis

from cybersectool.config import settings as app_config

_OTP_PREFIX = "kg:mfa:otp:"
OTP_TTL_SEC = 300  # 5 dakika

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


def generate_email_otp() -> str:
    """Kriptografik olarak güvenli 6 haneli OTP üretir."""
    return f"{secrets.randbelow(1_000_000):06d}"


def _hash(code: str) -> str:
    return hashlib.sha256(code.strip().encode("utf-8")).hexdigest()


async def store_email_otp(user_id: int, code: str, ttl: int = OTP_TTL_SEC) -> None:
    """Kodun hash'ini kullanıcıya bağlı anahtara TTL ile yazar (best-effort)."""
    with contextlib.suppress(Exception):
        await _redis().set(_OTP_PREFIX + str(user_id), _hash(code), ex=ttl)


async def verify_email_otp(user_id: int, code: str) -> bool:
    """OTP'yi doğrular; doğruysa siler (tek kullanımlık). Redis hatası → False."""
    cleaned = (code or "").strip()
    if not cleaned:
        return False
    key = _OTP_PREFIX + str(user_id)
    try:
        stored = await _redis().get(key)
    except Exception:
        return False
    if not stored or stored != _hash(cleaned):
        return False
    with contextlib.suppress(Exception):
        await _redis().delete(key)
    return True
