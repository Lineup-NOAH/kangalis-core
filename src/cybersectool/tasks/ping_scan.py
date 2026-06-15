"""Ping taraması (host keşfi) Celery görevi — scope'tan geçer, nmap -sn çalıştırır.

Port taraması YAPMAZ; yalnızca hedef aralığında hangi hostların AYAKTA olduğunu bulur
(nmap ``-sn``) ve bunları Asset envanterine yazar. NAT'lı/güvenlik-duvarlı ağlarda
ICMP tek başına yetmediğinden TCP SYN/ACK problarıyla keşif güçlendirilir
(bkz. ``DISCOVERY_NMAP_OPTIONS``).
"""

from __future__ import annotations

import asyncio
import contextlib

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from cybersectool.config import settings
from cybersectool.core.app_settings import get_settings
from cybersectool.core.audit import log_action
from cybersectool.core.infra import own_infra_ips
from cybersectool.core.models import ScanStatus
from cybersectool.core.scan_policy import (
    DISCOVERY_NMAP_OPTIONS,
    dns_nmap_options,
    nmap_exclude_option,
)
from cybersectool.core.scans import get_scan, set_scan_progress, set_scan_status
from cybersectool.core.scope import ScopeError, validate_target
from cybersectool.scanners.network import DiscoveredHost, run_ping_scan, store_discovery
from cybersectool.tasks.celery_app import celery_app


async def _run(scan_id: int, target: str) -> str:
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as session:
            options = DISCOVERY_NMAP_OPTIONS
            # Ağ/DNS ayarları (VI-6): reverse-DNS açıksa hostname çözümü, kapalıysa -n.
            app_cfg = await get_settings(session)
            dns_opts = dns_nmap_options(app_cfg.dns_servers, app_cfg.reverse_dns_enabled)
            if dns_opts:
                options = f"{options} {dns_opts}"
            # Aracın kendi altyapı container IP'lerini keşiften dışla (VI-7).
            exclude_opt = nmap_exclude_option(own_infra_ips())
            if exclude_opt:
                options = f"{options} {exclude_opt}"
            # Tek blok ya da boşlukla ayrılmış çok blok (zone=tek tarama). Her bloğu
            # scope guard'dan ayrı geçir.
            allowed_blocks: list[str] = []
            for block in target.split():
                try:
                    await validate_target(session, block)
                    allowed_blocks.append(block)
                except ScopeError:
                    continue
            if not allowed_blocks:
                await set_scan_status(session, scan_id, ScanStatus.failed)
                await log_action(session, "ping_scan_denied", target=target)
                return "scope_denied"

            await set_scan_status(session, scan_id, ScanStatus.running)
            # Her bloğu AYRI nmap koşusunda tara (tek scan kaydı korunur). Böylece büyük
            # var-olmayan aralıklar (NAT'ta gecikmeli/gürültülü) gerçek aralığın probelarını
            # boğmaz; karışık çok-bloklu hedefte güvenilir sonuç (WSL2/NAT). IP'ye göre tekil.
            hosts: list[DiscoveredHost] = []
            seen_ips: set[str] = set()
            total = len(allowed_blocks)
            for idx, block in enumerate(allowed_blocks):
                current = await get_scan(session, scan_id)
                if current is not None and current.status == ScanStatus.cancelled:
                    return "cancelled"
                pct = 15 + int(60 * idx / total)
                await set_scan_progress(
                    session, scan_id, pct, f"{block}: ping taraması ({idx + 1}/{total})"
                )
                block_hosts = await asyncio.to_thread(run_ping_scan, block, options)
                for host in block_hosts:
                    if host.ip not in seen_ips:
                        seen_ips.add(host.ip)
                        hosts.append(host)

            await set_scan_progress(session, scan_id, 80, "Ayakta hostlar envantere yazılıyor")
            count = await store_discovery(session, scan_id, hosts)
            await set_scan_progress(session, scan_id, 100, "Tamamlandı")
            await set_scan_status(session, scan_id, ScanStatus.completed)
            await log_action(session, "ping_scan", target=f"{target} ({count} ayakta host)")
            return f"completed:{count}"
    finally:
        await engine.dispose()


async def _mark_failed(scan_id: int, target: str, reason: str) -> None:
    """Beklenmeyen hata → ping taramasını 'başarısız' işaretle (takılı 'running' kalmasın)."""
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    try:
        async with async_sessionmaker(engine, expire_on_commit=False)() as session:
            await set_scan_status(session, scan_id, ScanStatus.failed)
            with contextlib.suppress(Exception):
                await log_action(session, "ping_scan_failed", target=f"{target}: {reason[:120]}")
    finally:
        await engine.dispose()


@celery_app.task(name="ping_scan")
def ping_scan_task(scan_id: int, target: str) -> str:
    try:
        return asyncio.run(_run(scan_id, target))
    except Exception as exc:  # nmap/işleme hatası → ping taraması 'başarısız' (takılı kalmaz)
        with contextlib.suppress(Exception):
            asyncio.run(_mark_failed(scan_id, target, str(exc)))
        return "failed"
