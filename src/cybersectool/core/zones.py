"""Zone (tarama bölgesi) servis fonksiyonları.

Zone = isimli bir IP/CIDR blok grubu. Taramalar bir zone seçilerek toplu başlatılabilir.
Zone yalnızca hedefleri **organize eder**; yetkilendirme hâlâ scope guard'a tabidir —
zone'daki her blok tarama anında scope'tan geçer, kapsam dışı bloklar atlanır.

`parse_cidr_input` / `validate_cidrs` saftır (birim testi edilebilir).
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.core.models import Zone


def parse_cidr_input(raw: str) -> list[str]:
    """Çok satırlı / virgüllü metni temiz IP/CIDR/URL listesine çevirir."""
    entries: list[str] = []
    for chunk in raw.replace(",", "\n").splitlines():
        entry = chunk.strip()
        if entry:
            entries.append(entry)
    return entries


def is_url_entry(entry: str) -> bool:
    """Girdi geçerli bir http(s) URL'si mi? (zone'a URL hedefi eklenebilir)."""
    if "://" not in entry:
        return False
    try:
        parsed = urlparse(entry)
    except ValueError:
        return False
    return parsed.scheme in ("http", "https") and bool(parsed.hostname)


def validate_cidrs(cidrs: list[str]) -> list[str]:
    """Her girdinin geçerli IP/CIDR YA DA http(s) URL olduğunu doğrular; değilse ValueError.

    URL girdileri tarama anında ayrılır: host/IP/CIDR'ler ağ taramasına; URL'ler web
    denetimine + host'u çözülerek ağ taramasına gider (SR-3c + URL-zone). Böylece bir zone
    hem IP blokları hem belirli web URL'lerini bir arada tutabilir.
    """
    if not cidrs:
        raise ValueError("En az bir IP/CIDR ya da URL girilmeli.")
    invalid: list[str] = []
    for entry in cidrs:
        if is_url_entry(entry):
            continue
        try:
            ipaddress.ip_network(entry, strict=False)
        except ValueError:
            invalid.append(entry)
    if invalid:
        raise ValueError(f"Geçersiz IP/CIDR/URL: {', '.join(invalid)}")
    return cidrs


async def create_zone(
    session: AsyncSession, name: str, cidrs: list[str], description: str | None = None
) -> Zone:
    zone = Zone(name=name, cidrs=validate_cidrs(cidrs), description=description)
    session.add(zone)
    await session.commit()
    await session.refresh(zone)
    return zone


async def update_zone(
    session: AsyncSession,
    zone_id: int,
    name: str,
    cidrs: list[str],
    description: str | None = None,
) -> Zone | None:
    """Bir zone'un adını/açıklamasını/IP bloklarını günceller (CIDR'ler doğrulanır)."""
    zone = await session.get(Zone, zone_id)
    if zone is None:
        return None
    zone.name = name
    zone.cidrs = validate_cidrs(cidrs)
    zone.description = description
    await session.commit()
    await session.refresh(zone)
    return zone


async def list_zones(session: AsyncSession) -> list[Zone]:
    result = await session.execute(select(Zone).order_by(Zone.id.desc()))
    return list(result.scalars().all())


async def get_zone(session: AsyncSession, zone_id: int) -> Zone | None:
    return await session.get(Zone, zone_id)


async def delete_zone(session: AsyncSession, zone_id: int) -> bool:
    zone = await session.get(Zone, zone_id)
    if zone is None:
        return False
    await session.delete(zone)
    await session.commit()
    return True


async def count_zones(session: AsyncSession) -> int:
    result = await session.execute(select(func.count()).select_from(Zone))
    return int(result.scalar_one() or 0)
