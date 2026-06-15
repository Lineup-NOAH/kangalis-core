"""Varsayılan/zayıf kimlik denetimi testleri (VI-12) — enjekte edilen auth ile."""

from __future__ import annotations

from cybersectool.core.default_creds import (
    DEFAULT_SSH_CREDS,
    MAX_DEFAULT_CRED_ATTEMPTS,
    creds_for_service,
)
from cybersectool.scanners.default_creds import check_ssh_default_creds


def test_creds_for_service() -> None:
    """SSH (ad veya port 22) → varsayılan liste; diğer servisler → boş."""
    assert creds_for_service("ssh", 22) == DEFAULT_SSH_CREDS
    assert creds_for_service("openssh", 2222) == DEFAULT_SSH_CREDS  # ad ssh
    assert creds_for_service(None, 22) == DEFAULT_SSH_CREDS  # port 22
    assert creds_for_service("http", 80) == ()  # SSH değil
    # Liste deneme sınırını aşmaz (brute-force değil).
    assert len(creds_for_service("ssh", 22)) <= MAX_DEFAULT_CRED_ATTEMPTS


async def test_check_finds_default_cred() -> None:
    """Yalnızca root/root kabul eden sunucu → tek KRİTİK bulgu (root/root)."""

    async def auth(host: str, port: int, user: str, pw: str) -> bool:
        return (user, pw) == ("root", "root")

    hits = await check_ssh_default_creds("10.0.0.5", 22, auth=auth)
    assert len(hits) == 1
    assert (hits[0].username, hits[0].password) == ("root", "root")


async def test_check_no_default_cred() -> None:
    """Hiçbir varsayılan kabul edilmiyor → bulgu yok."""

    async def auth(host: str, port: int, user: str, pw: str) -> bool:
        return False

    assert await check_ssh_default_creds("10.0.0.5", 22, auth=auth) == []


async def test_check_stops_after_first_success() -> None:
    """Hepsi kabul edilse bile İLK başarıda durur (brute-force değil)."""
    calls = 0

    async def auth(host: str, port: int, user: str, pw: str) -> bool:
        nonlocal calls
        calls += 1
        return True

    hits = await check_ssh_default_creds("10.0.0.5", 22, auth=auth)
    assert len(hits) == 1
    assert calls == 1  # ilk denemede durdu


async def test_check_respects_max_attempts() -> None:
    """max_attempts=1 → yalnız ilk kimlik denenir (2.'de tutacak olsa bile bulunmaz)."""
    tried: list[tuple[str, str]] = []

    async def auth(host: str, port: int, user: str, pw: str) -> bool:
        tried.append((user, pw))
        return (user, pw) == DEFAULT_SSH_CREDS[1]  # 2. kimlik tutar

    hits = await check_ssh_default_creds("10.0.0.5", 22, auth=auth, max_attempts=1)
    assert hits == []
    assert len(tried) == 1  # yalnız 1 deneme yapıldı


async def test_check_auth_exception_graceful() -> None:
    """auth bağlantı hatası fırlatırsa → çökmez, o deneme atlanır."""

    async def auth(host: str, port: int, user: str, pw: str) -> bool:
        raise OSError("connection refused")

    assert await check_ssh_default_creds("10.0.0.5", 22, auth=auth) == []
