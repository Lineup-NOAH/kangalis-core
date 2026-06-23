"""Ağ tarama Celery görevi — scope'tan geçer, nmap çalıştırır, sonuçları yazar."""

from __future__ import annotations

import asyncio
import contextlib
import math
import threading
from datetime import UTC, datetime
from typing import Any

import redis.asyncio as aioredis
from celery import chord
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from cybersectool.config import settings
from cybersectool.core.app_settings import get_settings
from cybersectool.core.assets import list_assets
from cybersectool.core.audit import log_action
from cybersectool.core.compliance import store_compliance
from cybersectool.core.cpe import match_service_cves_offline
from cybersectool.core.findings import create_finding
from cybersectool.core.infra import own_infra_ips
from cybersectool.core.masking import mask_password
from cybersectool.core.models import ScanMode, ScanStatus, ScanType, Service, Severity
from cybersectool.core.notify import notify_if_critical
from cybersectool.core.scan_policy import (
    DISCOVERY_NMAP_OPTIONS,
    dns_nmap_options,
    does_exploitation,
    estimate_scan_seconds,
    examined_port_scope,
    is_aggressive,
    nmap_exclude_option,
    nmap_options_for,
    parse_mode,
    partition_scan_targets,
    scan_speed_options,
    should_port_fanout,
    split_host_queue,
    split_port_queue,
    target_needs_chunking,
)
from cybersectool.core.scans import get_scan, set_scan_progress, set_scan_status
from cybersectool.core.scope import ScopeError, validate_target
from cybersectool.core.vuln import apply_risk_scores, enrich_cves, match_service_cves
from cybersectool.scanners.credentialless_compliance import run_credentialless_compliance
from cybersectool.scanners.default_creds import check_ssh_default_creds
from cybersectool.scanners.exposed_services import scan_exposed_services
from cybersectool.scanners.network import (
    HostResult,
    host_result_from_dict,
    host_result_to_dict,
    run_nmap,
    run_ping_scan,
    scan_block_hosts,
    store_nse_findings,
    store_results,
)
from cybersectool.scanners.rpc_probe import RPC_EPM_PORT, RPC_SMB_PORTS, audit_rpc
from cybersectool.tasks.celery_app import celery_app


async def _default_cred_findings(
    session: AsyncSession, scan_id: int, target: str, results: list[HostResult]
) -> int:
    """Agresif modda keşfedilen SSH servislerine varsayılan kimlik denetimi (VI-12).

    Salt-okunur, servis başına en fazla 3 deneme (lockout-farkında). Başarı → KRİTİK
    doğrulanmış bulgu. Yalnız agresif (admin + ack) yolundan çağrılır.
    """
    assets_by_ip = {a.ip: a.id for a in await list_assets(session)}
    total = 0
    for host in results:
        asset_id = assets_by_ip.get(host.ip)
        for svc in host.services:
            if svc.name not in ("ssh", "openssh") and svc.port != 22:
                continue
            hits = await check_ssh_default_creds(host.ip, svc.port, service_name=svc.name)
            for hit in hits:
                await create_finding(
                    session,
                    scan_id,
                    title=(
                        # Parola MASKELENİR (#141): bulgu raporda/PDF'te viewer dahil herkese
                        # görünür; müşterinin canlı parolasını düz metin sızdırmamak için.
                        f"Varsayılan SSH kimliği: {hit.username}/{mask_password(hit.password)} "
                        f"({host.ip}:{hit.port})"
                    ),
                    severity=Severity.critical,
                    asset_id=asset_id,
                    description=(
                        "Servis bilinen bir VARSAYILAN kimlikle girişe izin veriyor — "
                        "derhal parolayı değiştirin / hesabı devre dışı bırakın."
                    ),
                    validated=True,
                )
                total += 1
    if total:
        await log_action(
            session, "default_cred_check", target=f"{target} ({total} varsayılan kimlik)"
        )
    return total


async def _exposed_service_findings(
    session: AsyncSession, scan_id: int, results: list[HostResult]
) -> int:
    """Açık portlarda kimliksiz servis denetimi (#142): Redis/Elasticsearch unauth (salt-okunur).

    Her host için nmap'in bulduğu açık portlardan ilgili servisleri kimlik-doğrulamasız
    yoklar (Redis INFO / Elastic GET); erişim varsa kritik/yüksek bulgu yazar. Hiçbir şey
    değiştirmez; best-effort (bir host'taki hata diğerlerini engellemez).
    """
    assets_by_ip = {a.ip: a.id for a in await list_assets(session)}
    total = 0
    for host in results:
        open_ports = {svc.port for svc in host.services if svc.port}
        if not open_ports:
            continue
        for finding in await scan_exposed_services(host.ip, open_ports):
            await create_finding(
                session,
                scan_id,
                title=finding.title,
                severity=finding.severity,
                asset_id=assets_by_ip.get(host.ip),
                description=finding.description,
                validated=True,
            )
            total += 1
    if total:
        await log_action(
            session, "exposed_service_check", target=f"scan {scan_id} ({total} kimliksiz servis)"
        )
    return total


async def _rpc_probe_findings(
    session: AsyncSession, scan_id: int, results: list[HostResult]
) -> list[str]:
    """SMB/RPC portu açık host'larda versiyon-CVE OLMAYAN açıkları yoklar (#168 RPC-PROBE).

    PrintNightmare (CVE-2021-1675/34527) gibi açıklar Print Spooler'ın MS-RPRN RPC arayüzünden
    sömürülür; bir sürüm banner'ı sızdırmadıklarından sürüm→CVE eşleştirmesi bunları ASLA
    yakalayamaz. Bu yardımcı, 445/139 (SMB) ya da 135 (endpoint mapper) açık olan her host'ta
    impacket ile Spooler RPC arayüzünün uzaktan erişilebilir olup olmadığını SALT-OKUNUR doğrular
    (bind eder; sömürü primitifini ASLA çağırmaz). Bulgular ``validated=False`` (erişilebilirlik
    doğrulanır ama yamasızlık kanıtlanmaz). Üretilen CVE id'leri döner → CVE eşleştirme/risk
    aşamasında zenginleştirilir (Zafiyetler sayfasında görünür). Best-effort: bir host'taki hata
    diğerlerini engellemez (çağıran uçta da ``suppress``).
    """
    assets_by_ip = {a.ip: a.id for a in await list_assets(session)}
    cve_ids: list[str] = []
    total = 0
    for host in results:
        open_ports = {svc.port for svc in host.services if svc.port}
        smb_port = next((p for p in RPC_SMB_PORTS if p in open_ports), None)
        epm_open = RPC_EPM_PORT in open_ports
        if smb_port is None and not epm_open:
            continue  # RPC/SMB yüzeyi yok → probe atlanır
        with contextlib.suppress(Exception):
            _info, findings = await audit_rpc(host.ip, smb_port=smb_port, epm_open=epm_open)
            for f in findings:
                await create_finding(
                    session,
                    scan_id,
                    title=f.title,
                    severity=f.severity,
                    asset_id=assets_by_ip.get(host.ip),
                    cve_id=f.cve_id,
                    description=f.detail,
                    validated=False,
                )
                if f.cve_id:
                    cve_ids.append(f.cve_id)
                total += 1
    if total:
        await log_action(session, "rpc_probe", target=f"scan {scan_id} ({total} RPC bulgusu)")
    return cve_ids


async def _match_cves_for_service(
    session: AsyncSession, scan_id: int, service: Service, *, is_vuln: bool
) -> list[str]:
    """Bir servisi CVE'lerle eşleştirir; eşleşen cve_id'leri döndürür.

    CVE/CPE bilgi bankası ile Exploit/Payload DB ayrıldıktan sonra (patron kararı):
    - **Güvenli CVE taraması**: YALNIZ yerel CVE/CPE bankası (``match_service_cves_offline``,
      ağsız, offline CPE eşleştirme). Tarama başına canlı NVD çağrısı YOK — banka zaten
      arka planda senkron/backfill ile güncel tutulur.
    - **Zafiyet (derin) taraması**: yerel eşleştirme + ek olarak canlı NVD ile genişletme
      (``match_service_cves``), yerel pencerenin dışındaki/eski CVE'leri de yakalamak için.
    """
    matched = await match_service_cves_offline(session, scan_id, service)
    if is_vuln:
        with contextlib.suppress(Exception):
            matched = matched + await match_service_cves(session, scan_id, service)
    return matched


async def _run_nmap_with_progress(
    session: AsyncSession,
    scan_id: int,
    target: str,
    options: str,
    *,
    mode: str | ScanMode | None,
    ports: str | None,
    include_udp: bool,
    pct_floor: int = 10,
) -> list[HostResult]:
    """nmap'i arka planda çalıştırır; bu sırada ilerleme çubuğunu DÜZGÜN ilerletir (donma yok).

    nmap canlı ilerleme bildirmediğinden (çıktıyı pipe'ta tamponlar; stats yalnız çok-uzun
    görevlerde gecikmeli gelir), çubuk hedef-boyutu + mod'a dayalı bir ZAMAN tahminiyle
    %10→~%48 arası ASİMPTOTİK ilerletilir (nmap bitince işleme aşamaları %55+'tan devam eder).
    Böylece "uzun süre %10'da donup birden %70'e zıplama" ve ETA'nın 73dk→5dk yo-yo'su biter.
    ETA (rota katmanında ``_eta_seconds``) aynı tahminden türetilir → stabil + azalan.

    İptal (#160): her tikte taramanın durumu yoklanır; kullanıcı "Taramayı Durdur" dediyse
    ``cancel`` bayrağı set edilir ve ``run_nmap`` çalışan nmap sürecini ÖLDÜRÜR (arka planda
    orphan nmap kalmaz). ``set_scan_progress`` her tikte ``session.refresh`` ettiğinden durum
    DB'den (iptal eden rotanın commit'inden) tazedir.
    """
    est = max(estimate_scan_seconds(target, mode, ports, include_udp=include_udp), 30)
    tau = est / 3.0  # asimptotik zaman sabiti (~est'te %95'ine ulaşır; aşılırsa ~%48'de yavaşlar)
    label = f"{target[:80]}: nmap port taraması"
    cancel = threading.Event()
    fut = asyncio.ensure_future(asyncio.to_thread(run_nmap, target, options, cancel))
    start = datetime.now(UTC)
    while True:
        done, _ = await asyncio.wait({fut}, timeout=3.0)
        if done:
            break
        elapsed = (datetime.now(UTC) - start).total_seconds()
        # pct_floor → ~48 asimptotik (parçalı keşif sonrası port taraması %26'dan başlayabilir).
        pct = pct_floor + int((48 - pct_floor) * (1.0 - math.exp(-elapsed / tau)))
        with contextlib.suppress(Exception):
            await set_scan_progress(session, scan_id, min(pct, 48), label)
        # İptal yoklaması: "Durdur" dendiyse nmap'i öldür (yoksa orphan dakikalarca koşar).
        cur = await get_scan(session, scan_id)
        if cur is not None and cur.status == ScanStatus.cancelled:
            cancel.set()
    return await fut


async def _discover_hosts_chunked(
    session: AsyncSession,
    scan_id: int,
    blocks: list[str],
    discovery_options: str,
    *,
    concurrency: int = 4,
) -> list[str]:
    """Büyük CIDR bloklarını blok-blok (sertleştirilmiş -sn) tarayıp CANLI host IP'lerini döner.

    SCAN-NET Faz 1: tek dev nmap süpürmesi araya giren NAT'ı boğup gerçek hostları kaçırabildiği
    için (canlı ölçüm: /24 → 0), hedef küçük bloklara bölünür ve her blok ayrı keşfedilir. Bloklar
    ``concurrency`` kadar PARALEL (asyncio.to_thread) ama parti-parti (batch) çalışır: nmap işi
    iş parçacığında, oturum (DB) erişimi parti aralarında SERİ yapılır — AsyncSession eşzamanlı
    kullanılamaz. Her partiden önce iptal yoklanır; "Durdur" → kalan bloklar atlanır. İlerleme
    %10→~%26 bandında (port taraması sonra %26+'dan devam eder).
    """
    cancel = threading.Event()
    up: set[str] = set()
    total = len(blocks)
    width = max(1, concurrency)
    done = 0
    for start_idx in range(0, total, width):
        cur = await get_scan(session, scan_id)
        if cur is not None and cur.status == ScanStatus.cancelled:
            cancel.set()
            break
        batch = blocks[start_idx : start_idx + width]
        # nmap keşifleri paralel (iş parçacığı) — oturuma DOKUNMAZ (eşzamanlılık güvenli).
        results = await asyncio.gather(
            *(asyncio.to_thread(run_ping_scan, block, discovery_options, cancel) for block in batch)
        )
        for hosts in results:
            up.update(h.ip for h in hosts)
        done += len(batch)
        pct = 10 + int(16 * done / total)  # 10 → ~26
        with contextlib.suppress(Exception):
            await set_scan_progress(
                session, scan_id, min(pct, 26), f"Host keşfi (parçalı) {done}/{total} blok"
            )
    return sorted(up)


async def _run(scan_id: int, target: str, mode: str) -> str:
    scan_mode = parse_mode(mode)
    # Derinlemesine savunma (#1): global kill-switch (ALLOW_AGGRESSIVE_SCANS) kapalıyken,
    # route gate atlatılsa/eski bir agresif iş kuyrukta kalsa bile worker AGRESİF çalışmaz —
    # güvenli moda düşer (agresif NSE + varsayılan-kimlik + exploitation atlanır).
    aggressive_blocked = is_aggressive(scan_mode) and not settings.allow_aggressive_scans
    if aggressive_blocked:
        scan_mode = ScanMode.safe
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as session:
            # Tarama kaydından port seçimi + tür (zafiyet) bilgisini oku.
            scan = await get_scan(session, scan_id)
            ports = scan.ports if scan is not None else None
            is_vuln = scan is not None and scan.scan_type == ScanType.vuln
            want_udp = scan is not None and scan.include_udp
            options = nmap_options_for(scan_mode, ports, include_udp=want_udp)
            # Ağ/DNS ayarları (VI-6): özel DNS sunucusu + reverse-DNS aç/kapa.
            app_cfg = await get_settings(session)
            dns_opts = dns_nmap_options(app_cfg.dns_servers, app_cfg.reverse_dns_enabled)
            if dns_opts:
                options = f"{options} {dns_opts}"
            # Aracın kendi altyapı container IP'lerini (db/redis/app...) taramadan dışla (VI-7).
            exclude_opt = nmap_exclude_option(own_infra_ips())
            if exclude_opt:
                options = f"{options} {exclude_opt}"
            # Tarama hızı (SCAN-SPEED): nmap paralellik bayrakları (Ayarlar'dan). nmap ağ-bound →
            # hız RAM/CPU değil PARALELLİKLE artar; boştaki kaynağı çok-hostlu taramada kullan.
            speed_opts = scan_speed_options(app_cfg.scan_speed)
            if speed_opts:
                options = f"{options} {speed_opts}"
            # Hedef tek bir blok ya da boşlukla ayrılmış çok blok olabilir (zone=tek
            # tarama). Her bloğu scope guard'dan ayrı geçir; izinlileri tek nmap koşusunda
            # birleştir (defense-in-depth: dispatch da doğrular).
            allowed_blocks: list[str] = []
            for block in target.split():
                try:
                    await validate_target(session, block)
                    allowed_blocks.append(block)
                except ScopeError:
                    continue
            if not allowed_blocks:
                await set_scan_status(session, scan_id, ScanStatus.failed)
                await log_action(session, "network_scan_denied", target=target)
                return "scope_denied"
            scan_target = " ".join(allowed_blocks)

            if aggressive_blocked:
                await log_action(
                    session,
                    "aggressive_downgraded",
                    target=f"{target}: ALLOW_AGGRESSIVE_SCANS kapalı → güvenli moda düşüldü",
                )

            await set_scan_status(session, scan_id, ScanStatus.running)
            # Büyük CIDR hedefleri bloklara bölünür (NAT boğulmasını önler — Faz 1). Fan-out AÇIKSA
            # (Faz 2b) bloklar Celery chord ile WORKER'LARA dağıtılır (tek tarama worker sayısıyla
            # ~doğrusal hızlanır); merge task sonuçları birleştirir. Fan-out KAPALIYSA Faz 1 tek-
            # worker blok-blok keşfine düşülür. Küçük/tek hedefler eskisi gibi tek geçişte taranır.
            if target_needs_chunking(scan_target):
                explicit_targets, blocks = partition_scan_targets(scan_target)
                port_options = f"{options} -Pn"  # bloklar keşiften sonra -Pn ile derin taranır
                discovery_options = DISCOVERY_NMAP_OPTIONS
                if exclude_opt:
                    discovery_options = f"{discovery_options} {exclude_opt}"
                if app_cfg.scan_fanout:
                    return await _dispatch_fanout(
                        session,
                        scan_id,
                        target,
                        scan_mode,
                        blocks,
                        explicit_targets,
                        port_options,
                        discovery_options,
                        ports=ports,
                        want_udp=want_udp,
                        dns_opts=dns_opts,
                        exclude_opt=exclude_opt,
                        speed_opts=speed_opts,
                        workers=app_cfg.fanout_workers,
                    )
                # Fallback (fan-out kapalı): Faz 1 tek-worker blok-blok keşif → -Pn derin tarama.
                await set_scan_progress(session, scan_id, 10, "Host keşfi (parçalı)")
                live_hosts = await _discover_hosts_chunked(
                    session, scan_id, blocks, discovery_options
                )
                scan_list = explicit_targets + live_hosts
                results = (
                    await _run_nmap_with_progress(
                        session,
                        scan_id,
                        " ".join(scan_list),
                        port_options,
                        mode=scan_mode,
                        ports=ports,
                        include_udp=want_udp,
                        pct_floor=26,
                    )
                    if scan_list
                    else []
                )
            elif (
                app_cfg.scan_fanout
                and app_cfg.fanout_workers > 1
                and should_port_fanout(ports, include_udp=want_udp, workers=app_cfg.fanout_workers)
            ):
                # PORT-QUEUE (#171): tek/küçük host'u portlara böl → TÜM taramalar worker kullanır
                # (port sayısı ≥ worker sayısı; varsayılan top-1000 dahil). Portlar N=worker yerine
                # M>>N KÜÇÜK partiye bölünür → Celery havuzu dinamik çeker (kimse boş durmaz, ağır
                # NSE doğal yayılır). Tarama hızından BAĞIMSIZ — açma/kapama + worker sayısı
                # Ayarlar'da (scan_fanout + fanout_workers); her child yine seçilen hız (slow→-T2).
                # Merge'te STALE-PRUNE KOŞULLU (tüm partiler başarılıysa). workers≤1 → bölme yok.
                return await _dispatch_port_fanout(
                    session,
                    scan_id,
                    target,
                    scan_target,
                    scan_mode,
                    ports,
                    dns_opts,
                    exclude_opt,
                    speed_opts,
                    app_cfg.fanout_workers,
                )
            else:
                await set_scan_progress(
                    session, scan_id, 10, f"{scan_target[:80]}: nmap port taraması"
                )
                # nmap çalışırken çubuk %10→~%48 düzgün ilerler (donma/zıplama yok); bitince %55+.
                results = await _run_nmap_with_progress(
                    session,
                    scan_id,
                    scan_target,
                    options,
                    mode=scan_mode,
                    ports=ports,
                    include_udp=want_udp,
                )

            return await _process_results(
                session, scan_id, target, scan_mode, results, is_vuln=is_vuln
            )
    finally:
        await engine.dispose()


async def _process_results(
    session: AsyncSession,
    scan_id: int,
    target: str,
    scan_mode: ScanMode,
    results: list[HostResult],
    *,
    is_vuln: bool,
    prune: bool = True,
) -> str:
    """nmap sonrası işleme (TEK doğruluk kaynağı): store + exposed + NSE + CVE + risk + sömürü.

    Hem tek-worker yolu (``_run``) hem fan-out birleştirme task'ı (``_merge_and_process``) bunu
    çağırır. İptal yoklanır; iptal edilmişse pahalı işlem atlanır (durum 'cancelled' korunur).

    ``prune=False`` ise STALE-PRUNE atlanır — PORT-FANOUT'ta tek host PORT'a göre bölündüğünden
    bir child çökerse o port aralığının GERÇEK servisleri "görülmedi" sanılıp silinebilir
    (yanlış-negatif). Port-fanout merge bunu ``False`` geçer; normal/CIDR taramalarda ``True``.
    """
    current = await get_scan(session, scan_id)
    if current is not None and current.status == ScanStatus.cancelled:
        return "cancelled"
    await set_scan_progress(session, scan_id, 55, "Servisler/varlıklar işleniyor")
    # STALE-PRUNE: bu taramanın incelediği port kapsamı → store_results, yanıt veren host'ta bu
    # taramada GÖRÜLMEYEN eski servisleri (örn. artık açık olmayan "tcpwrapped") eskitir/siler.
    # Tarama kaydı okunamazsa (current None) kapsam bilinemez → budama yapılmaz (güvenli taraf).
    port_scope = (
        examined_port_scope(current.ports, include_udp=current.include_udp)
        if current is not None and prune
        else None
    )
    services = await store_results(session, results, port_scope=port_scope)
    # Kimliksiz exposed-servis denetimi (#142): Redis/Elasticsearch unauth (salt-okunur).
    await set_scan_progress(session, scan_id, 60, "Kimliksiz servis denetimi")
    with contextlib.suppress(Exception):
        await _exposed_service_findings(session, scan_id, results)
    # RPC probe (#168): SMB/RPC açık host'larda versiyon-CVE OLMAYAN açıklar (PrintNightmare/
    # Spooler MS-RPRN). Salt-okunur bind; sürüm→CVE eşleştirmesinin yapısal olarak kaçırdığı
    # CVE'leri yakalar. Her modda çalışır (exposed_services gibi non-intrusive). CVE id'leri
    # matched_ids'e eklenir → zenginleştirilir + Zafiyetler'e akar.
    await set_scan_progress(session, scan_id, 62, "RPC zafiyet probe'u (PrintNightmare)")
    rpc_cve_ids: list[str] = []
    with contextlib.suppress(Exception):
        rpc_cve_ids = await _rpc_probe_findings(session, scan_id, results)
    # Agresif modda NSE vuln/exploit script'lerinin AKTİF doğruladığı bulgular
    # (validated=True). Güvenli modda script çalışmaz → liste boş (VI-13).
    nse_cve_ids = await store_nse_findings(session, scan_id, results)
    # Agresif modda (admin + ack) keşfedilen SSH'lere varsayılan-kimlik denetimi (VI-12).
    if is_aggressive(scan_mode):
        await set_scan_progress(session, scan_id, 65, "Varsayılan kimlik denetimi (SSH)")
        await _default_cred_findings(session, scan_id, target, results)
    cve_phase = "Zafiyet analizi (CVE + KEV/EPSS)" if is_vuln else "CVE eşleştiriliyor"
    await set_scan_progress(session, scan_id, 70, cve_phase)
    matched_ids: list[str] = list(nse_cve_ids) + rpc_cve_ids
    for service in services:
        matched_ids.extend(
            await _match_cves_for_service(session, scan_id, service, is_vuln=is_vuln)
        )
    unique_ids = list(set(matched_ids))
    await set_scan_progress(session, scan_id, 90, "CVE zenginleştirme + risk skorları")
    await enrich_cves(session, unique_ids)
    await apply_risk_scores(session, unique_ids)
    # İŞLEME SIRASINDA İPTAL: kullanıcı canlı "Durdur" dediyse pahalı exploit fazını ATLA +
    # 'tamamlandı' ile EZME. İptal yalnız en başta (yukarıda) yoklanıyordu; CVE/exploit fazı
    # dakikalarca sürdüğünden o pencerede gelen iptal sessizce kaybolur, tarama "tamamlandı"
    # görünürdü (üstelik iptal edilmiş taramada exploit ateşlenebilirdi).
    if await _scan_cancelled(session, scan_id):
        return "cancelled"
    # Sömürme taraması (vuln + exploit modu): CVE tespiti + exploit DENEMESİ — iki kaynak.
    # SR-1: gerçek sömürü ARTIK YALNIZ ``exploit`` modunda (does_exploitation). Agresif CVE
    # sömürmez — yalnız tespit eder + kullanılabilir exploit'leri gösterir (rapor/canlı).
    # (1) Metasploit: msfrpcd yapılandırılmışsa doğrulanmış/olası CVE'lere GERÇEK
    #     exploitation dener (VIII-2b). Kapılar (admin + ack + scope) çağıran uçta +
    #     runner'da; her deneme audit'lenir. msfrpcd yoksa sessizce atlanır.
    # (2) Exploit-DB: eşleşen PoC'ler "staged" ExploitAttempt olarak hazırlanır (EXDB-A)
    #     — msfrpcd GEREKTİRMEZ, hiçbir şey çalıştırmaz; operatör (ya da sandbox, EXDB-C)
    #     labda dener. Böylece Metasploit kapalı olsa bile Exploit-DB devreye girer.
    # LİSANS KAPISI: ``exploit`` sömürüsü için geçerli ticari lisans GEREKİR — eklenti kurulu
    # olsa bile lisans yoksa sömürü fazı hiç başlamaz (tespit/rapor tam sürer).
    from cybersectool.core.licensing import feature_licensed

    if is_vuln and does_exploitation(scan_mode) and await feature_licensed(session, "exploit"):
        created_by = current.created_by if current is not None else None
        # Sömürü eklentisi (kapalı/ticari, opsiyonel) — açık-kaynak çekirdekte bulunmayabilir.
        # GEÇ/KOŞULLU import: paket yoksa tespit tam tamamlanır, yalnız sömürü fazı atlanır.
        try:
            from cybersectool.exploit import msf_client
            from cybersectool.exploit.exploitdb_stage import stage_exploitdb_attempts
            from cybersectool.exploit.runner import run_exploitation_for_scan
        except ImportError:
            pass
        else:
            if msf_client.msf_configured():
                await set_scan_progress(session, scan_id, 95, "Agresif CVE exploitation (MSF)")
                with contextlib.suppress(Exception):
                    await run_exploitation_for_scan(session, scan_id, user_id=created_by)
            await set_scan_progress(session, scan_id, 97, "Exploit-DB PoC eşleştirme")
            with contextlib.suppress(Exception):
                await stage_exploitdb_attempts(session, scan_id, user_id=created_by)
    # Son iptal yoklaması: exploit fazı sürerken gelen "Durdur" da 'tamamlandı' ile ezilmesin.
    if await _scan_cancelled(session, scan_id):
        return "cancelled"
    # Kimliksiz uyum (roadmap #E): taramanın açık-servis/yönetim-portu/HTTP uyum sonuçlarını
    # türet → mevcut ComplianceCheck tablosuna sakla (KVKK/ISO/PCI tablosunda kimlikli denetimlerle
    # birlikte görünür). tls_checked=False: ağ taraması check_tls çalıştırmaz → 443 açık olsa bile
    # TLS denetlenmemiştir (sahte TLS-pass üretilmez; TLS denetimleri web taramasına aittir).
    # Best-effort: hata taramayı bozmaz.
    with contextlib.suppress(Exception):
        cl_results = await run_credentialless_compliance(
            session, scan_id, services=services, tls_checked=False
        )
        if cl_results:
            await store_compliance(session, scan_id, cl_results)
    await notify_if_critical(session, scan_id, target)
    await set_scan_progress(session, scan_id, 100, "Tamamlandı")
    await set_scan_status(session, scan_id, ScanStatus.completed)
    await log_action(
        session,
        "network_scan",
        target=f"{target} [{scan_mode}] ({len(services)} servis, {len(unique_ids)} CVE)",
    )
    return f"completed:{scan_mode}:{len(services)}:{len(unique_ids)}"


async def _scan_cancelled(session: AsyncSession, scan_id: int) -> bool:
    """Tarama bu sırada (canlı) iptal edildi mi? — worker session'ında TAZE DB okuması.

    İptal rotası AYRI bir transaction'da ``cancelled`` yazar; worker'ın identity-map'indeki
    Scan nesnesi bayat kalabileceğinden ``refresh`` ile yeniden okunur (READ COMMITTED → rotanın
    commit'ini görür). İşleme/exploit fazı uzun sürdüğünden bu yoklama o pencerede yapılır.
    """
    scan = await get_scan(session, scan_id)
    if scan is None:
        return False
    await session.refresh(scan)
    return scan.status == ScanStatus.cancelled


async def _mark_failed(scan_id: int, target: str, reason: str) -> None:
    """Beklenmeyen hata → taramayı 'başarısız' işaretle + neden bulgusu (takılı 'running' kalmasın).

    nmap çalıştırma/parse ya da işleme hatasında tarama sonsuza dek 'running'/%10'da
    asılı kalmasın diye ayrı bir oturumda durum=failed yazılır ve hangi taramanın neden
    başarısız olduğunu belirten bir bulgu eklenir (kullanıcı raporda görür).
    """
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    try:
        async with async_sessionmaker(engine, expire_on_commit=False)() as session:
            await set_scan_status(session, scan_id, ScanStatus.failed)
            with contextlib.suppress(Exception):
                await create_finding(
                    session,
                    scan_id,
                    f"Tarama başarısız: {target[:80]}",
                    severity=Severity.info,
                    description=f"Ağ taraması tamamlanamadı (nmap/işleme hatası): {reason[:300]}",
                )
            with contextlib.suppress(Exception):
                await log_action(session, "network_scan_failed", target=f"{target}: {reason[:120]}")
    finally:
        await engine.dispose()


async def _incr_blocks_done(scan_id: int) -> int:
    """Bir blok bitti → Redis sayacını atomik artır (fan-out ilerlemesi için). Yeni değeri döner.

    İstemci ÇAĞRI BAŞINA yaratılıp kapatılır. Worker'da her görev ``asyncio.run`` ile YENİ bir
    event loop açtığından, süreç-ömürlü önbelleğe-alınmış async istemci 2. taramada "Event loop is
    closed" hatası verirdi (istemci kapanmış loop'a bağlı kalır). Çağrı-başına istemci her zaman
    GEÇERLİ (çalışan) loop'a bağlıdır.
    """
    client = aioredis.from_url(settings.redis_url, decode_responses=True)  # type: ignore[no-untyped-call]
    try:
        key = f"kg:scan:{scan_id}:blocks_done"
        done = int(await client.incr(key))
        await client.expire(key, 3600)
        return done
    finally:
        await client.aclose()


async def _reset_blocks_done(scan_id: int) -> None:
    """Fan-out başlamadan blok sayacını sıfırla (yeniden taramada eski değer kalmasın)."""
    client = aioredis.from_url(settings.redis_url, decode_responses=True)  # type: ignore[no-untyped-call]
    try:
        await client.delete(f"kg:scan:{scan_id}:blocks_done")
    finally:
        await client.aclose()


async def _dispatch_fanout(
    session: AsyncSession,
    scan_id: int,
    target: str,
    scan_mode: ScanMode,
    blocks: list[str],
    explicit_targets: list[str],
    port_options: str,
    discovery_options: str,
    *,
    ports: str | None,
    want_udp: bool,
    dns_opts: str,
    exclude_opt: str,
    speed_opts: str,
    workers: int,
) -> str:
    """BİRLEŞİK DİSPATCHER: Faz 1 keşif → Faz 2 canlı host'ları worker havuzuna DİNAMİK dağıt.

    ESKİ CIDR fan-out her /27 bloğu için keşif+derin taramayı TEK child'a koyuyordu → boş bloklar
    worker israf ediyor, host-yoğun blok tek child'da SERİ taranıyordu (efektif paralellik = host'lu
    blok sayısı, çekirdek sayısı DEĞİL — yoğun /24'te 16 çekirdeğin yalnız 1-2'si dolardı). YENİ
    model (patron tasarımı, PORT-QUEUE #171'in host-boyutuna taşınması):

    * **Faz 1 — KEŞİF:** büyük bloklar blok-blok (-sn) taranıp TÜM canlı host'lar toplanır
      (NAT-güvenli ``_discover_hosts_chunked``). Açıkça yazılan host'lar (explicit) keşfi ATLAR →
      her zaman derin taranır (kullanıcı niyeti, -Pn). Hiç canlı host yoksa boş sonuç işlenir.
    * **Faz 2 — DAĞIT:** canlı host listesi 16 çekirdeği dolduracak iş birimine bölünür + dinamik
      çekilir (biten worker sıradakini alır): (a) host sayısı ≥ worker → HOST-QUEUE (host'ları
      M>>N küçük partiye böl); (b) az host ama çok port (-p-/top-1000) → PORT-QUEUE (o host'ların
      PORT uzayını böl); (c) az host + az port → HOST-QUEUE (host başına tiny child; tek host →
      tek parti = tek geçiş, overhead yok).

    İş birimi kör IP bloğu DEĞİL gerçek yük (canlı host) → yoğun /24'te 16 çekirdek dolu, boş alanda
    worker israfı yok, son-ağır-blok takılması yok. Parent chord dağıtınca DÖNER (bloklamaz).
    """
    # Faz 1 — KEŞİF: büyük blokları blok-blok (-sn) tarayıp canlı host'ları topla (NAT-güvenli).
    await set_scan_progress(session, scan_id, 10, "Faz 1 — host keşfi (parçalı)")
    live = await _discover_hosts_chunked(session, scan_id, blocks, discovery_options)
    # explicit (tek IP / küçük CIDR / hostname) keşfi atlar → her zaman derin taranır (kaçırılmaz).
    deep_targets = explicit_targets + live
    if not deep_targets:
        # Hiç canlı host yok → boş sonuç işle (tarama 'tamamlandı', 0 bulgu; chord'a gerek yok).
        await set_scan_progress(session, scan_id, 55, "Canlı host bulunamadı")
        scan = await get_scan(session, scan_id)
        is_vuln = scan is not None and scan.scan_type == ScanType.vuln
        return await _process_results(session, scan_id, target, scan_mode, [], is_vuln=is_vuln)

    # Faz 2 — DAĞIT: canlı host'ları worker havuzunu dolduracak boyutta böl + dinamik çek.
    many_hosts = len(deep_targets) >= max(2, workers)
    if not many_hosts and should_port_fanout(ports, include_udp=want_udp, workers=workers):
        # (b) Az host ama çok port → PORT-QUEUE: o host'ların PORT uzayını böl (havuzu doldur).
        return await _dispatch_port_fanout(
            session,
            scan_id,
            target,
            " ".join(deep_targets),
            scan_mode,
            ports,
            dns_opts,
            exclude_opt,
            speed_opts,
            workers,
        )
    # (a)+(c) Bol host VEYA az-port → HOST-QUEUE: canlı host'ları M>>N partiyle havuza dağıt.
    return await _dispatch_host_queue(
        session, scan_id, target, scan_mode, deep_targets, port_options, workers
    )


async def _dispatch_host_queue(
    session: AsyncSession,
    scan_id: int,
    target: str,
    scan_mode: ScanMode,
    hosts: list[str],
    port_options: str,
    workers: int,
) -> str:
    """HOST-QUEUE (Birleşik Dispatcher Faz 2): canlı host'ları M>>N küçük partiye böler.

    PORT-QUEUE'nun (#171) host-boyutu İKİZİ: ``split_host_queue`` host'ları round-robin M partiye
    böler (M = N × oversubscribe, host sayısıyla kısılı); her parti bir child task = o host'ların
    ``-Pn`` derin taraması (keşif Faz 1'de bitti → ``discover=False``). Müdür = Celery broker,
    çalışanlar = prefork havuzu → partileri DİNAMİK çeker (work-stealing): ağır host'lu parti uzun
    sürerken boşalan worker hafif partiyi alır, kimse boş durmaz. Her host TEK partide (overlap yok)
    → ``_merge_host_results`` no-op, per-host prune güvenli → ``fanout_kind`` varsayılan "cidr"
    (prune açık kalır; düşen partinin host'u sonuçta olmaz → gerçek servis yanlışlıkla budanmaz).
    Tek host → tek parti = tek geçiş (fan-out overhead'i olmadan doğru sonuç).
    """
    batches = split_host_queue(hosts, workers, heavy=is_aggressive(scan_mode))
    children = [
        network_scan_block_task.s(scan_id, " ".join(batch), port_options, "", False, len(batches))
        for batch in batches
    ]
    await _reset_blocks_done(scan_id)
    await set_scan_progress(
        session,
        scan_id,
        26,
        f"Faz 2 — {len(hosts)} canlı host {len(batches)} partiyle worker havuzuna dağıtıldı",
    )
    # chord(header)(callback): tüm partiler bitince merge birleştirir + CVE/risk/sömürü işler.
    chord(children)(network_scan_merge_task.s(scan_id, target, str(scan_mode)))
    await log_action(
        session,
        "network_scan_host_queue",
        target=f"{target} ({len(hosts)} host / {len(batches)} parti)",
    )
    return f"host_queue:{len(batches)}"


async def _dispatch_port_fanout(
    session: AsyncSession,
    scan_id: int,
    target: str,
    scan_target: str,
    scan_mode: ScanMode,
    ports: str | None,
    dns_opts: str,
    exclude_opt: str,
    speed_opts: str,
    workers: int,
) -> str:
    """PORT-QUEUE (#171): tek host'un PORT uzayını M>>N KÜÇÜK partiye böler (dinamik iş kuyruğu).

    CIDR-fanout host'a göre böler; bu PORT'a göre. ESKİ PORT-FANOUT portları SABİT N=worker
    parçaya bölüyordu → bir parça çok açıksa (ağır NSE) diğer worker'lar boş bekliyordu (son-blok
    takılması). PORT-QUEUE portları ``split_port_queue`` ile **M >> N** küçük strided partiye böler:
    müdür = Celery broker kuyruğu, çalışanlar = prefork havuzu (eşzamanlılık=CPU); havuz partileri
    DİNAMİK çeker → bir çalışan bitince sıradakini alır, kimse boş durmaz (work-stealing). Parti
    sayısı operatörün ``fanout_workers`` (N) ayarı × oversubscribe (mod ağırsa daha çok); tarama
    HIZINDAN BAĞIMSIZ (``scan_fanout`` açar/kapatır); her child yine seçilen hız profilini kullanır
    (slow→ ``-T2``). Her child AYNI host'u farklı ``-p`` alt-kümesi + ``-Pn`` ile tarar
    (``discover=False``); chord callback (merge) M sonucu birleştirir. STALE-PRUNE merge'te KOŞULLU
    (``fanout_kind="port"``): tüm partiler başarılıysa budar, biri düşerse atlar → eksik aralıktaki
    gerçek servis yanlışlıkla budanmaz.
    """
    specs = split_port_queue(ports, workers, heavy=is_aggressive(scan_mode))
    children = []
    for spec in specs:
        child_opts = nmap_options_for(scan_mode, spec, include_udp=False)
        for extra in (dns_opts, exclude_opt, speed_opts):
            if extra:
                child_opts = f"{child_opts} {extra}"
        child_opts = f"{child_opts} -Pn"  # açıkça yazılan tek host → keşif atla (parçalı dal gibi)
        children.append(
            network_scan_block_task.s(scan_id, scan_target, child_opts, "", False, len(specs))
        )
    await _reset_blocks_done(scan_id)
    # %26: child partileri 26→50 raporlar (keşif sonrası taban; birleşik dispatcher'dan da
    # çağrılınca keşif zaten %26'ya getirdiğinden geriye-zıplama olmaz; standalone'da monotonik).
    await set_scan_progress(
        session,
        scan_id,
        26,
        f"Dinamik iş-kuyruğu: {len(specs)} küçük port partisi worker havuzuna dağıtıldı",
    )
    # fanout_kind="port" → merge prune'u KOŞULLU yapar: tüm port-child'lar başarılıysa budar,
    # biri düşerse atlar (taranamayan port aralığındaki gerçek servisi yanlışlıkla silmesin).
    chord(children)(network_scan_merge_task.s(scan_id, target, str(scan_mode), "port"))
    await log_action(
        session,
        "network_scan_port_fanout",
        target=f"{target} ({len(specs)} port partisi / iş kuyruğu)",
    )
    return f"port_fanned_out:{len(specs)}"


async def _scan_one_block(
    scan_id: int,
    block: str,
    port_options: str,
    discovery_options: str,
    discover: bool,
    total: int,
) -> list[dict[str, Any]]:
    """Tek bir bloğu tarar (fan-out child) → JSON-güvenli host dict listesi.

    nmap iş parçacığında koşarken durum yoklanır; "Durdur" → ``cancel`` set edilir, nmap öldürülür
    (#160). Bittiğinde Redis blok sayacı artırılır + ilerleme (%10→~50) güncellenir.
    """
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    cancel = threading.Event()
    try:
        async with factory() as session:
            cur = await get_scan(session, scan_id)
            if cur is not None and cur.status == ScanStatus.cancelled:
                return []
            fut = asyncio.ensure_future(
                asyncio.to_thread(
                    scan_block_hosts, block, port_options, discovery_options, discover, cancel
                )
            )
            while True:
                done, _ = await asyncio.wait({fut}, timeout=3.0)
                if done:
                    break
                cur = await get_scan(session, scan_id)
                if cur is not None and cur.status == ScanStatus.cancelled:
                    cancel.set()
            results = await fut
            done_n = await _incr_blocks_done(scan_id)
            # Keşif (Faz 1) bitince çubuk %26 → derin tarama partileri 26→~50 (merge sonra %55+).
            pct = 26 + int(24 * done_n / max(total, 1))
            with contextlib.suppress(Exception):
                await set_scan_progress(
                    session, scan_id, min(pct, 50), f"Derin tarama {done_n}/{total} parti"
                )
            return [host_result_to_dict(h) for h in results]
    finally:
        await engine.dispose()


@celery_app.task(name="network_scan_block")
def network_scan_block_task(
    scan_id: int,
    block: str,
    port_options: str,
    discovery_options: str,
    discover: bool,
    total: int,
) -> list[dict[str, Any]]:
    """Fan-out child task: bir bloğu tarar. Hata olsa bile [] döner (chord + bloklar sürer)."""
    try:
        return asyncio.run(
            _scan_one_block(scan_id, block, port_options, discovery_options, discover, total)
        )
    except Exception:  # bir blok düşse de tarama tümden çökmesin (chord ilerler, merge toparlar)
        with contextlib.suppress(Exception):
            asyncio.run(_incr_blocks_done(scan_id))  # sayaç tutarlı kalsın
        return []


def _merge_host_results(results: list[HostResult]) -> list[HostResult]:
    """Aynı IP için birden çok HostResult'ı tek HostResult'a birleştirir (PORT-fanout için ŞART).

    PORT-fanout'ta her child AYNI host'u farklı port alt-kümesiyle tarar → merge'e aynı IP için N
    AYRI HostResult gelir. ``store_results`` bunları ayrı host sanıp her blokta upsert+prune yapar →
    bir önceki bloğun servislerini siler (clobber) ve silinen Service nesnelerine sonraki CVE
    fazında erişince tarama PATLAR. Burada IP başına servisler ``(port, protocol)`` ile dedup edilip
    ``nse_findings`` toplanır → tek HostResult → ``store_results`` bir kez DOĞRU prune yapar.
    CIDR-fanout'ta her child farklı host'lar tarar → IP çakışmaz, no-op (zararsız).
    """
    merged: dict[str, HostResult] = {}
    for h in results:
        cur = merged.get(h.ip)
        if cur is None:
            merged[h.ip] = HostResult(
                ip=h.ip,
                hostname=h.hostname,
                services=list(h.services),
                nse_findings=list(h.nse_findings),
            )
            continue
        seen = {(s.port, s.protocol) for s in cur.services}
        for s in h.services:
            if (s.port, s.protocol) not in seen:
                cur.services.append(s)
                seen.add((s.port, s.protocol))
        cur.nse_findings.extend(h.nse_findings)
        if cur.hostname is None and h.hostname:
            cur.hostname = h.hostname
    return list(merged.values())


async def _merge_and_process(
    block_results: list[list[dict[str, Any]]],
    scan_id: int,
    target: str,
    mode: str,
    fanout_kind: str = "cidr",
) -> str:
    """Fan-out child sonuçlarını birleştirip işler (chord callback'i) → ``_process_results``.

    STALE-PRUNE port-fan-out'ta KOŞULLU: ``fanout_kind == "port"`` (tek host PORT'a bölündü) ise
    prune YALNIZ tüm port-child'lar başarılıysa çalışır. Her port-child host'u ``-Pn`` ile tarar →
    başarılıysa host'u döndürür (boş blok = o child DÜŞTÜ). Bir child düşerse, taranamayan port
    aralığındaki GERÇEK servis yanlışlıkla budanmasın diye prune atlanır → sonraki (tam başarılı)
    taramada budanır. CIDR fan-out'ta prune güvenlidir (per-host; düşen bloğun host'u sonuçta yok →
    budanmaz) → her zaman açık. Tek-worker yolu da bunu ``_process_results`` içinde yapar.
    """
    scan_mode = parse_mode(mode)
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as session:
            scan = await get_scan(session, scan_id)
            is_vuln = scan is not None and scan.scan_type == ScanType.vuln
            blocks = block_results or []
            raw = [host_result_from_dict(d) for block in blocks for d in (block or [])]
            # KRİTİK (clobber/crash fix): PORT-fanout'ta aynı IP için N HostResult gelir → tek
            # HostResult'a birleştir; yoksa store_results her blokta prune ile öncekini siler.
            results = _merge_host_results(raw)
            # PORT-fan-out: tek host port'a bölündü → prune yalnız HİÇBİR port-child düşmemişse
            # (tüm bloklar dolu). Boş blok = o port aralığı taranamadı → prune onu silmesin.
            prune = all(bool(b) for b in blocks) if fanout_kind == "port" else True
            return await _process_results(
                session, scan_id, target, scan_mode, results, is_vuln=is_vuln, prune=prune
            )
    finally:
        await engine.dispose()


@celery_app.task(name="network_scan_merge")
def network_scan_merge_task(
    block_results: list[list[dict[str, Any]]],
    scan_id: int,
    target: str,
    mode: str,
    fanout_kind: str = "cidr",
) -> str:
    """Fan-out chord callback: bloklar bitince çağrılır → birleştir + işle + tamamla."""
    try:
        return asyncio.run(_merge_and_process(block_results, scan_id, target, mode, fanout_kind))
    except Exception as exc:  # birleştirme/işleme hatası → tarama 'başarısız' (takılı kalmaz)
        with contextlib.suppress(Exception):
            asyncio.run(_mark_failed(scan_id, target, str(exc)))
        return "failed"


@celery_app.task(name="network_scan")
def network_scan_task(scan_id: int, target: str, mode: str = "safe") -> str:
    try:
        return asyncio.run(_run(scan_id, target, mode))
    except Exception as exc:  # nmap/parse/işleme hatası → tarama 'başarısız' (takılı kalmaz)
        with contextlib.suppress(Exception):
            asyncio.run(_mark_failed(scan_id, target, str(exc)))
        return "failed"
