"""Varsayılan/zayıf kimlik denetimi tarayıcısı (VI-12) — yalnız agresif + ack.

Keşfedilen SSH servislerine KÜÇÜK küratörlü varsayılan-parola listesini dener
(salt-okunur: yalnızca kimlik doğrular, KOMUT ÇALIŞTIRMAZ). İlk başarıda durur,
servis başına en fazla ``MAX_DEFAULT_CRED_ATTEMPTS`` deneme (lockout-farkında).
Bir başarı = KRİTİK bulgu. TAM brute-force DEĞİL.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import asyncssh

from cybersectool.core.default_creds import (
    MAX_DEFAULT_CRED_ATTEMPTS,
    creds_for_service,
)
from cybersectool.core.models import Severity

# Bir kimlik denemesini yürüten fonksiyon imzası (test için enjekte edilebilir).
AuthFn = Callable[[str, int, str, str], Awaitable[bool]]


@dataclass
class DefaultCredHit:
    host: str
    port: int
    username: str
    password: str
    severity: Severity = Severity.critical


async def ssh_auth(
    host: str, port: int, username: str, password: str, timeout: float = 8.0
) -> bool:
    """SSH ile YALNIZCA kimlik doğrular (salt-okunur; komut çalıştırmaz). Başarı→True."""
    try:
        async with asyncssh.connect(
            host,
            port=port,
            username=username,
            password=password,
            known_hosts=None,
            connect_timeout=timeout,
        ):
            return True
    except (TimeoutError, asyncssh.Error, OSError):
        return False


async def check_ssh_default_creds(
    host: str,
    port: int,
    *,
    service_name: str | None = "ssh",
    auth: AuthFn = ssh_auth,
    max_attempts: int = MAX_DEFAULT_CRED_ATTEMPTS,
) -> list[DefaultCredHit]:
    """Bir SSH servisine varsayılan kimlikleri dener; ilk başarıda durur (lockout-farkında).

    En fazla ``max_attempts`` deneme yapılır. ``auth`` enjekte edilebilir (test).
    """
    pairs = creds_for_service(service_name, port)
    hits: list[DefaultCredHit] = []
    attempts = 0
    for username, password in pairs:
        if attempts >= max_attempts:
            break
        attempts += 1
        try:
            ok = await auth(host, port, username, password)
        except (TimeoutError, asyncssh.Error, OSError):
            continue  # bağlantı/kilit hatası → bu denemeyi atla (gürültü çıkarma)
        if ok:
            hits.append(DefaultCredHit(host=host, port=port, username=username, password=password))
            break  # bir tane yeterli; daha fazla deneme brute-force'a yaklaşır → DUR
    return hits
