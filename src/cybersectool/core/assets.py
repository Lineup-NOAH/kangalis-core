"""Varlık (asset) ve servis envanteri için servis fonksiyonları."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlparse

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.core.models import Asset, Scan, Service


async def upsert_asset(
    session: AsyncSession,
    ip: str,
    hostname: str | None = None,
    os: str | None = None,
    name: str | None = None,
    is_up: bool = False,
) -> Asset:
    """IP'ye göre varlığı oluşturur ya da günceller (idempotent).

    ``name`` kullanıcı tarafından verilen cihaz adıdır; taramalar bu alanı
    geçmez, bu yüzden güncellemede asla üzerine yazılmaz (hostname ile aynı desen).
    ``is_up=True`` → host bir tarama/ping ile AYAKTA doğrulandı (yapışkan: bir kez
    ayakta görülen host False'a düşürülmez; envanterde gösterilir).
    """
    result = await session.execute(select(Asset).where(Asset.ip == ip))
    asset = result.scalar_one_or_none()
    if asset is None:
        asset = Asset(ip=ip, hostname=hostname, os=os, name=name, is_up=is_up)
        session.add(asset)
    else:
        if hostname is not None:
            asset.hostname = hostname
        if os is not None:
            asset.os = os
        if name is not None:
            asset.name = name
        if is_up:
            asset.is_up = True
        asset.last_seen = datetime.now(UTC)
    await session.commit()
    await session.refresh(asset)
    return asset


async def create_url_asset(session: AsyncSession, url: str, name: str | None = None) -> Asset:
    """Elle eklenen tekil URL varlığı (ip=NULL). URL'ye göre idempotent.

    Patron isteği: envantere bir web hedefi (URL) eklenip web/normal taramada kullanılsın.
    ``is_up=True`` verilir ki gerçek-cihaz filtresinden geçip envanterde görünsün. URL
    kimliği (şema/host/port/yol) korunur; ağ taraması anında host'u çözülür (URL-zone akışı).
    """
    result = await session.execute(select(Asset).where(Asset.url == url))
    asset = result.scalar_one_or_none()
    if asset is None:
        asset = Asset(url=url, name=name, is_up=True)
        session.add(asset)
    elif name is not None:
        asset.name = name
    await session.commit()
    await session.refresh(asset)
    return asset


async def upsert_service(
    session: AsyncSession,
    asset_id: int,
    port: int,
    protocol: str = "tcp",
    service_name: str | None = None,
    product: str | None = None,
    version: str | None = None,
    cpe: str | None = None,
) -> Service:
    """(asset, port, protocol) anahtarına göre servisi oluşturur ya da günceller."""
    result = await session.execute(
        select(Service).where(
            Service.asset_id == asset_id,
            Service.port == port,
            Service.protocol == protocol,
        )
    )
    service = result.scalar_one_or_none()
    if service is None:
        service = Service(
            asset_id=asset_id,
            port=port,
            protocol=protocol,
            service_name=service_name,
            product=product,
            version=version,
            cpe=cpe,
        )
        session.add(service)
    else:
        if service_name is not None:
            service.service_name = service_name
        if product is not None:
            service.product = product
        if version is not None:
            service.version = version
        if cpe is not None:
            service.cpe = cpe
        service.last_seen = datetime.now(UTC)
    await session.commit()
    await session.refresh(service)
    return service


async def prune_unseen_services(
    session: AsyncSession,
    asset_id: int,
    seen: set[tuple[int, str]],
    scope: dict[str, set[int] | None],
) -> int:
    """STALE-PRUNE: bu taramada GÖRÜLMEYEN (artık açık olmayan) servisleri envanterden siler.

    Tarama, yanıt veren bir host'u yeniden incelediğinde, eskiden bulunup bu sefer açık
    OLMAYAN servisler envanterde "hayalet" kayıt olarak kalıyordu (``upsert_service`` yalnız
    ekler/günceller, asla silmez; nmap parse'ı ``state != open`` portu atlar). Sonuç: bir kez
    yazılan ``tcpwrapped`` ya da kapanan bir servis bir daha değişmiyor. Bu fonksiyon o boşluğu
    kapatır.

    * ``seen`` = bu taramada bu varlıkta AÇIK bulunan ``(port, protocol)`` kümesi.
    * ``scope`` = ``examined_port_scope`` çıktısı (incelenen protokol→port): değer ``None`` ise o
      protokolde tüm portlar incelendi; küme ise yalnız o portlar; protokol sözlükte yoksa
      incelenmedi → o protokol hiç budanmaz.

    Yalnız (incelendi + bu taramada görülmedi) servisler silinir. Silinen satır sayısını döner.
    Çağıran YALNIZ yanıt veren (sonuç listesinde olan) host için çağırmalı — yanıt vermeyen/kapalı
    host'un envanteri korunur (tek bir kötü geçiş tüm envanteri silmesin).
    """
    result = await session.execute(select(Service).where(Service.asset_id == asset_id))
    removed = 0
    for svc in result.scalars().all():
        if (svc.port, svc.protocol) in seen:
            continue  # bu taramada hâlâ açık → koru
        if svc.protocol not in scope:
            continue  # bu protokol hiç incelenmedi → dokunma
        ports = scope[svc.protocol]
        if ports is not None and svc.port not in ports:
            continue  # taramanın kapsamı dışındaki port → dokunma
        await session.delete(svc)
        removed += 1
    if removed:
        await session.commit()
    return removed


async def set_asset_name(session: AsyncSession, asset_id: int, name: str | None) -> bool:
    """Varlığa kullanıcı tanımlı cihaz adı atar (boş → None, hostname'e geri düşer).

    ``upsert_asset`` IP anahtarlı ve ``last_seen`` bump eder; bu fonksiyon yalnız
    adı (id ile) değiştirir, son-görülme zamanına dokunmaz (elle yeniden adlandırma).
    """
    asset = await session.get(Asset, asset_id)
    if asset is None:
        return False
    cleaned = (name or "").strip()
    asset.name = cleaned or None
    await session.commit()
    return True


async def get_asset(session: AsyncSession, asset_id: int) -> Asset | None:
    return await session.get(Asset, asset_id)


async def list_assets(session: AsyncSession) -> list[Asset]:
    result = await session.execute(select(Asset).order_by(Asset.id))
    return list(result.scalars().all())


async def count_assets(session: AsyncSession) -> int:
    result = await session.execute(select(func.count()).select_from(Asset))
    return int(result.scalar_one() or 0)


def is_real_device(asset: Asset, *, asset_ids_with_service: set[int], infra_ips: set[str]) -> bool:
    """Bir varlığın 'gerçek cihaz' olup olmadığı (envanterde gösterilmeli mi).

    Görünür = aracın KENDİ altyapısı DEĞİL ve (tarama/ping ile AYAKTA doğrulandı ya da
    açık servisi VAR ya da kullanıcı adı verilmiş ya da hostname çözülmüş). Hiç yanıt
    vermemiş ham/karşılıksız çıplak IP'ler (is_up=False, servissiz, adsız) gizlenir —
    patron: 'gereksiz veri istemiyoruz, ağda yanıt veren cihaz varsa görmek istiyorum'.
    """
    if asset.ip in infra_ips:
        return False
    return (
        asset.is_up
        or asset.id in asset_ids_with_service
        or bool(asset.name)
        or bool(asset.hostname)
    )


async def list_inventory_assets(session: AsyncSession, *, show_all: bool = False) -> list[Asset]:
    """Görünür envanter varlıkları (gerçek cihazlar). ``show_all`` → filtreyi atla.

    Junk/boş IP'leri ve aracın kendi container IP'lerini eler (VI-10). ``show_all=True``
    operatöre ham listeyi (denetim/hata ayıklama) sunar.
    """
    assets = await list_assets(session)
    if show_all:
        return assets
    from cybersectool.core.infra import own_infra_ips

    infra_ips = own_infra_ips()
    services = await session.execute(select(Service.asset_id))
    with_service = {row[0] for row in services.all()}
    return [
        a
        for a in assets
        if is_real_device(a, asset_ids_with_service=with_service, infra_ips=infra_ips)
    ]


async def count_inventory_assets(session: AsyncSession) -> int:
    """Görünür envanter varlık sayısı (panel statcard'ı için)."""
    return len(await list_inventory_assets(session))


async def hosts_in_scope(session: AsyncSession, targets: list[str]) -> list[dict[str, object]]:
    """Verilen hedef(ler) kapsamındaki AYAKTA/gerçek cihazlar + bilgileri.

    Rapor ve canlı görünümün paylaştığı yardımcı. ``targets`` IP/CIDR listesi (birleşik
    ``"ip1 ip2"`` hedefler boşluğa göre ayrılır). Her host: ip, name (görünüm adı),
    hostname, os, is_up, services (port'a göre sıralı). Kendi altyapı IP'leri ve hiç
    yanıt vermemiş ham bare IP'ler (is_up=False, servissiz, adsız) hariç. ``targets``
    boşsa tüm gerçek cihazlar döner.
    """
    import ipaddress

    from cybersectool.core.infra import own_infra_ips

    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for tgt in targets:
        for block in tgt.split():
            try:
                nets.append(ipaddress.ip_network(block, strict=False))
            except ValueError:
                continue
    assets = await list_assets(session)
    svc_by_asset: dict[int, list[Service]] = {}
    for svc in await list_services(session):
        svc_by_asset.setdefault(svc.asset_id, []).append(svc)
    infra_ips = own_infra_ips()
    hosts: list[dict[str, object]] = []
    for asset in assets:
        # URL varlıkları (ip=NULL) IP-host listesinde yer almaz; web taraması kendi host
        # girdilerini (resolved_ip) üretir. Atlanmazsa aşağıdaki ip-sıralaması çöker.
        if asset.ip is None:
            continue
        if asset.ip in infra_ips:
            continue
        if nets:
            try:
                if not any(ipaddress.ip_address(asset.ip) in net for net in nets):
                    continue
            except ValueError:
                continue
        svcs = sorted(svc_by_asset.get(asset.id, []), key=lambda s: s.port)
        if not (asset.is_up or svcs or asset.name or asset.hostname):
            continue
        hosts.append(
            {
                "ip": asset.ip,
                "name": asset.display_name,
                "hostname": asset.hostname,
                "os": asset.os,
                "is_up": asset.is_up,
                "services": svcs,
            }
        )

    def _sort_key(h: dict[str, object]) -> tuple[int, int]:
        # IPv4 ve IPv6 adresleri DOĞRUDAN karşılaştırılamaz (TypeError) → önce sürüme (4<6),
        # sonra paketlenmiş tam-sayı değerine göre sırala. Geçersiz IP en sona düşer.
        try:
            addr = ipaddress.ip_address(str(h["ip"]))
        except ValueError:
            return (9, 0)
        return (addr.version, int(addr))

    hosts.sort(key=_sort_key)
    return hosts


@dataclass(frozen=True)
class _WebTargetService:
    """``hosts_in_scope`` host'larındaki Service ile aynı alanlara sahip sahte servis.

    Web taraması nmap port taraması yapmaz; taranan URL'in tek "servisi" şema/porttur
    (ör. 443/tcp https). Rapor/canlı şablonu host.services üzerinde döndüğü için aynı
    arayüzü (port/protocol/service_name/product/version) sağlamak yeterli.
    """

    port: int
    protocol: str = "tcp"
    service_name: str = ""
    product: str | None = None
    version: str | None = None


def web_scan_host_entries(scans: list[Scan]) -> list[dict[str, object]]:
    """Web taramaları için "taranan host" satırları (iç envanter DEĞİL).

    Her web taraması → hedef URL'in host'u + çözülen IP'si (``scan.resolved_ip``) +
    şema/port servisi. ``hosts_in_scope`` ile aynı sözlük şeklini döndürür ki rapor,
    PDF ve canlı şablonları değişmeden çalışsın. Çözülen IP yoksa (eski tarama / DNS
    hatası) IP "—" gösterilir.
    """
    entries: list[dict[str, object]] = []
    for s in scans:
        parsed = urlparse(s.target if "://" in s.target else f"http://{s.target}")
        host = parsed.hostname or s.target
        scheme = parsed.scheme or "http"
        port = parsed.port or (443 if scheme == "https" else 80)
        entries.append(
            {
                "ip": s.resolved_ip or "—",
                "name": host,
                "hostname": None,
                "os": None,
                "is_up": bool(s.resolved_ip),
                "services": [_WebTargetService(port=port, service_name=scheme)],
            }
        )
    return entries


async def services_for_target(session: AsyncSession, target: str) -> list[Service]:
    """Bir tarama hedefinin (IP/CIDR) kapsamındaki varlıkların açık servisleri (canlı görünüm).

    Hedef bir CIDR ya da tekil IP olabilir; o ağ/IP'ye düşen varlıkların portları döner.
    """
    import ipaddress

    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return []
    asset_ids: set[int] = set()
    for asset in await list_assets(session):
        if asset.ip is None:
            continue  # URL varlığı → IP/CIDR hedef kapsamına girmez
        try:
            if ipaddress.ip_address(asset.ip) in net:
                asset_ids.add(asset.id)
        except ValueError:
            continue
    if not asset_ids:
        return []
    result = await session.execute(
        select(Service).where(Service.asset_id.in_(asset_ids)).order_by(Service.port)
    )
    return list(result.scalars().all())


async def list_services(session: AsyncSession) -> list[Service]:
    result = await session.execute(select(Service).order_by(Service.asset_id, Service.port))
    return list(result.scalars().all())
