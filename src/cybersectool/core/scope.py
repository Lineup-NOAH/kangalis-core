"""Yetkili kapsam (scope) kontrolü.

Tarama yalnızca aktif `ScopePolicy`'de tanımlı **izinli** CIDR aralıklarının alt kümesi
olan ve **yasak** aralıklarla çakışmayan hedeflere izin verir. Tanımlı politika yoksa
varsayılan olarak reddedilir (default-deny).
"""

from __future__ import annotations

import ipaddress

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.core.infra import own_infra_ips
from cybersectool.core.models import ScopePolicy

IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class ScopeError(Exception):
    """Hedef yetkili kapsam dışında."""


def _network(value: str) -> IpNetwork:
    return ipaddress.ip_network(value, strict=False)


def _is_subnet(target: IpNetwork, parent: IpNetwork) -> bool:
    if isinstance(target, ipaddress.IPv4Network) and isinstance(parent, ipaddress.IPv4Network):
        return target.subnet_of(parent)
    if isinstance(target, ipaddress.IPv6Network) and isinstance(parent, ipaddress.IPv6Network):
        return target.subnet_of(parent)
    return False


def is_target_allowed(target: str, allowed: list[str], denied: list[str]) -> bool:
    """Hedef (IP veya CIDR) izinli kapsamda mı? Yasaklarla çakışırsa reddeder."""
    try:
        target_net = _network(target)
    except ValueError:
        return False

    for entry in denied:
        try:
            if target_net.overlaps(_network(entry)):
                return False
        except (ValueError, TypeError):
            continue

    for entry in allowed:
        try:
            allowed_net = _network(entry)
        except ValueError:
            continue
        if _is_subnet(target_net, allowed_net):
            return True

    return False


async def get_active_policy(session: AsyncSession) -> ScopePolicy | None:
    result = await session.execute(
        select(ScopePolicy).where(ScopePolicy.is_active.is_(True)).order_by(ScopePolicy.id.desc())
    )
    return result.scalars().first()


async def set_active_scope(
    session: AsyncSession,
    *,
    name: str,
    allowed_cidrs: list[str],
    denied_cidrs: list[str],
) -> ScopePolicy:
    """Yeni aktif kapsam politikası yazar (set_scope CLI ile AYNI davranış) — #C web formu.

    Önceki tüm politikalar pasifleştirilir, en yeni (en yüksek id) aktif olur; `get_active_policy`
    `id desc` ile onu seçer. CIDR doğrulaması ÇAĞIRANIN işidir (web formu
    `app_settings.parse_asset_scope_cidrs` ile doğrular). `validate_target` bunu okur — okuma
    mantığına DOKUNULMAZ. Commit edilir ve yeni politika döner.
    """
    await session.execute(update(ScopePolicy).values(is_active=False))
    policy = ScopePolicy(
        name=name,
        allowed_cidrs=allowed_cidrs,
        denied_cidrs=denied_cidrs,
        is_active=True,
    )
    session.add(policy)
    await session.commit()
    await session.refresh(policy)
    return policy


async def validate_target(session: AsyncSession, target: str) -> None:
    """Hedef yetkili kapsamda değilse `ScopeError` fırlatır."""
    policy = await get_active_policy(session)
    if policy is None:
        raise ScopeError("Tanımlı yetkili kapsam (scope) yok; tarama reddedildi.")
    if not is_target_allowed(target, policy.allowed_cidrs, policy.denied_cidrs):
        raise ScopeError(f"Hedef yetkili kapsam dışında: {target}")


def is_external_web_allowed(ip: str, denied: list[str], excluded: set[str]) -> bool:
    """Dış (public internet) web hedefi izinli mi? YALNIZ global/public IP'lere izin verir.

    İç-ağ scope guard'ından AYRI, kasıtlı olarak gevşek ama hâlâ korumalı bir kapı:
    SSRF ve iç-altyapı sızıntısını önlemek için global olmayan TÜM adresler (özel/RFC1918,
    loopback, link-local — 169.254.169.254 bulut metadata dâhil — multicast/ayrılmış)
    reddedilir; ayrıca aracın kendi altyapı IP'leri (``excluded``) ve politikada açıkça
    yasaklı (``denied``) bloklar reddedilir. İç hedefler normal scope guard'dan geçmelidir.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if not addr.is_global:
        return False
    if ip in excluded:
        return False
    target_net = ipaddress.ip_network(ip)
    for entry in denied:
        try:
            if target_net.overlaps(_network(entry)):
                return False
        except (ValueError, TypeError):
            continue
    return True


async def validate_external_web_target(session: AsyncSession, ip: str) -> None:
    """Dış web hedefi (çözülmüş IP) public değilse/yasaklıysa `ScopeError` fırlatır.

    Yalnız ``allow_external`` işaretli web taramaları için çağrılır (admin + açık onay).
    Politikadaki ``denied_cidrs`` yine geçerlidir; aracın kendi altyapısı dışlanır.
    """
    policy = await get_active_policy(session)
    denied = policy.denied_cidrs if policy is not None else []
    if not is_external_web_allowed(ip, denied, own_infra_ips()):
        raise ScopeError(
            f"Dış web hedefi yalnız public IP olabilir; iç/özel/yerel adres reddedildi: {ip}"
        )


def ip_in_asset_scope(ip: str, cidrs: list[str]) -> bool:
    """IP, varlık-kapsamı (asset scope) CIDR'lerinden birine düşüyor mu? (saf)

    Boş ``cidrs`` listesi → True (kapsam zorlanmaz, tüm IP'ler asset olabilir). Bu, tarama
    yetkisinden (ScopePolicy) BAĞIMSIZ bir envanter-allowlist'idir: yalnız buradaki IP'ler
    Varlıklar'a eklenir; dışındakiler (dış/public taramalar) envanteri kirletmez.
    """
    if not cidrs:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in cidrs:
        try:
            if addr in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue
    return False


async def should_be_asset(session: AsyncSession, ip: str) -> bool:
    """Bu IP envantere (Varlıklar) eklenmeli mi? Yalnız kapsam-içi (iç) IP'ler için True (F1).

    Ayarlardaki ``asset_scope_cidrs`` (varsayılan RFC1918 + loopback) okunur; dış/public
    hedeflere yapılan taramalar asset YARATMAZ (bulgular yine raporlanır).
    """
    from cybersectool.core.app_settings import get_settings

    row = await get_settings(session)
    return ip_in_asset_scope(ip, row.asset_scope_cidrs)
