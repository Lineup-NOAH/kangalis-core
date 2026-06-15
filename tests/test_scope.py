"""Yetkili kapsam (scope guard) testleri."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.models import ScopePolicy
from cybersectool.core.scope import (
    ScopeError,
    ip_in_asset_scope,
    is_external_web_allowed,
    is_target_allowed,
    should_be_asset,
    validate_external_web_target,
    validate_target,
)

ALLOWED = ["10.0.0.0/8", "192.168.0.0/16"]
DENIED = ["10.0.0.0/24"]


def test_subnet_of_allowed_is_ok() -> None:
    assert is_target_allowed("10.1.2.0/24", ALLOWED, DENIED) is True
    assert is_target_allowed("192.168.1.0/24", ALLOWED, DENIED) is True


def test_denied_range_is_rejected() -> None:
    assert is_target_allowed("10.0.0.5", ALLOWED, DENIED) is False


def test_outside_allowed_is_rejected() -> None:
    assert is_target_allowed("8.8.8.8", ALLOWED, DENIED) is False


def test_invalid_target_is_rejected() -> None:
    assert is_target_allowed("not-an-ip", ALLOWED, DENIED) is False


async def test_validate_target_without_policy_raises(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        with pytest.raises(ScopeError):
            await validate_target(session, "10.1.0.0/24")


async def test_validate_target_with_policy(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        session.add(
            ScopePolicy(name="t", allowed_cidrs=ALLOWED, denied_cidrs=DENIED, is_active=True)
        )
        await session.commit()

        await validate_target(session, "10.1.0.0/24")  # izinli → hata yok

        with pytest.raises(ScopeError):
            await validate_target(session, "8.8.8.8")
        with pytest.raises(ScopeError):
            await validate_target(session, "10.0.0.5")


# --- Dış (public internet) web hedefi guard'ı (yalnız-public; SSRF/iç-bypass koruması) ---


def test_external_web_allows_public_ip() -> None:
    assert is_external_web_allowed("8.8.8.8", [], set()) is True
    assert is_external_web_allowed("1.1.1.1", [], set()) is True


def test_external_web_rejects_private_and_local() -> None:
    # RFC1918 özel, loopback, link-local (bulut metadata 169.254.169.254 dâhil) → reddedilir.
    for ip in ("10.0.0.5", "192.168.1.10", "172.16.0.1", "127.0.0.1", "169.254.169.254"):
        assert is_external_web_allowed(ip, [], set()) is False


def test_external_web_rejects_invalid_excluded_and_denied() -> None:
    assert is_external_web_allowed("not-an-ip", [], set()) is False
    # Aracın kendi (dışlanan) altyapı IP'si public bile olsa reddedilir.
    assert is_external_web_allowed("203.0.113.10", [], {"203.0.113.10"}) is False
    # Politikada açıkça yasaklı public blok → reddedilir.
    assert is_external_web_allowed("203.0.113.10", ["203.0.113.0/24"], set()) is False


async def test_validate_external_web_target_public_ok_private_raises(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        await validate_external_web_target(session, "8.8.8.8")  # public → hata yok
        with pytest.raises(ScopeError):
            await validate_external_web_target(session, "10.0.0.5")  # iç → reddedilir
        with pytest.raises(ScopeError):
            await validate_external_web_target(session, "169.254.169.254")  # metadata → reddedilir


# --- Varlık kapsamı (F1; yalnız iç/kapsam-içi IP'ler envantere) ---

ASSET_SCOPE = ["10.0.0.0/8", "192.168.0.0/16", "203.0.113.10/32"]


def test_ip_in_asset_scope_basic() -> None:
    assert ip_in_asset_scope("10.1.2.3", ASSET_SCOPE) is True
    assert ip_in_asset_scope("192.168.1.5", ASSET_SCOPE) is True
    assert ip_in_asset_scope("203.0.113.10", ASSET_SCOPE) is True  # tek-IP /32
    assert ip_in_asset_scope("8.8.8.8", ASSET_SCOPE) is False  # dış → kapsam dışı
    assert ip_in_asset_scope("172.16.0.1", ASSET_SCOPE) is False  # listede yok


def test_ip_in_asset_scope_empty_means_all() -> None:
    # Boş kapsam = zorlanmaz (tüm IP'ler asset olabilir).
    assert ip_in_asset_scope("8.8.8.8", []) is True


def test_ip_in_asset_scope_invalid_and_ipv6() -> None:
    assert ip_in_asset_scope("not-an-ip", ASSET_SCOPE) is False
    assert ip_in_asset_scope("::1", ["::1/128"]) is True
    assert ip_in_asset_scope("2001:db8::1", ["::1/128"]) is False


async def test_should_be_asset_default_private_only(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Varsayılan kapsam (RFC1918 + loopback) → iç IP True, dış public IP False."""
    async with session_factory() as session:
        assert await should_be_asset(session, "10.0.0.5") is True
        assert await should_be_asset(session, "192.168.1.10") is True
        assert await should_be_asset(session, "8.8.8.8") is False  # dış → asset olmaz


async def test_should_be_asset_custom_scope_includes_external(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Operatör dış bir IP eklerse o IP asset kapsamına girer."""
    from cybersectool.core.app_settings import save_asset_scope_settings

    async with session_factory() as session:
        await save_asset_scope_settings(session, raw_cidrs="203.0.113.0/24")
        assert await should_be_asset(session, "203.0.113.10") is True  # eklendi → kapsam içi
        assert await should_be_asset(session, "10.0.0.5") is False  # artık listede değil
