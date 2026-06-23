"""Web tarama Celery görevi — güvenlik başlıkları + TLS denetimi (scope'tan geçer)."""

from __future__ import annotations

import asyncio
import contextlib
import socket
from collections.abc import Mapping
from urllib.parse import urlparse

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from cybersectool.config import settings
from cybersectool.core.assets import upsert_asset, upsert_service
from cybersectool.core.audit import log_action
from cybersectool.core.compliance import store_compliance
from cybersectool.core.cpe import find_matching_cves, match_service_cves_offline
from cybersectool.core.findings import create_finding
from cybersectool.core.models import CVE, ScanStatus, Severity
from cybersectool.core.notify import notify_if_critical
from cybersectool.core.scan_policy import does_exploitation, is_aggressive, parse_mode
from cybersectool.core.scans import get_scan, set_scan_progress, set_scan_status
from cybersectool.core.scope import (
    ScopeError,
    should_be_asset,
    validate_external_web_target,
    validate_target,
)
from cybersectool.core.vuln import apply_risk_scores, enrich_cves
from cybersectool.core.wordlists import get_wordlist
from cybersectool.scanners.credentialless_compliance import run_credentialless_compliance
from cybersectool.scanners.web import (
    WebFinding,
    active_dast,
    check_common_paths,
    check_cookie_flags,
    check_cors,
    check_info_disclosure,
    check_security_headers,
    check_tls,
    directory_scan,
    fetch_page,
    parse_server_banners,
)
from cybersectool.tasks.celery_app import celery_app


def pinned_url(target: str, ip: str) -> str:
    """Hedef URL/host'u DOĞRULANAN IP'ye pinler (TOCTOU/DNS-rebinding scope bypass'ı önler).

    Scope guard tek bir gethostbyname sonucunu (ip) doğrular; ardından gerçek istekler
    hostname kullanırsa httpx host'u BAĞIMSIZ yeniden çözer → round-robin/rebinding ile
    doğrulanan IP yerine kapsam dışı bir IP'ye bağlanılabilir. Bu yardımcı, bağlantıyı
    doğrulanan ip'ye sabitleyip şema/port/path/query'yi korur. host zaten IP ise değişmez
    (no-op). (vhost gerekiyorsa hedefi IP ile verin; iç ağ tarayıcısı için kabul edilir.)
    """
    parsed = urlparse(target if "://" in target else f"http://{target}")
    scheme = parsed.scheme or "http"
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or ""
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return f"{scheme}://{ip}:{port}{path}"


async def _web_cve_findings(
    session: AsyncSession,
    scan_id: int,
    ip: str,
    port: int,
    scheme: str,
    headers: Mapping[str, str],
) -> list[str]:
    """Web yığını banner'ından (Server/X-Powered-By) yerel CVE'leri bulur (SR-3a, banner→CVE).

    Güvenli çıkarım (sömürmez): yalnız yanıt başlığındaki ürün/sürümü yerel CVE/CPE bankasıyla
    eşleştirir. **Kapsam içi (asset-scope) host** → asset+service oluşturulur ki CVE bulguları
    first-class olsun (Zafiyetler'e girer + ileride web sömürüsüne hazır). **Kapsam dışı/dış URL**
    → bulgular asset_id=None (raporda exploit görünürlüğüyle gösterilir, envanteri kirletmez).
    """
    triples = parse_server_banners(headers)
    if not triples:
        return []
    asset_id: int | None = None
    if await should_be_asset(session, ip):
        asset = await upsert_asset(session, ip, is_up=True)
        asset_id = asset.id
    matched: list[str] = []
    for vendor, product, version in triples:
        cpe = f"cpe:/a:{vendor}:{product}:{version}"
        if asset_id is not None:
            service = await upsert_service(
                session,
                asset_id,
                port,
                "tcp",
                service_name=scheme,
                product=product,
                version=version,
                cpe=cpe,
            )
            matched.extend(await match_service_cves_offline(session, scan_id, service))
        else:
            for cve_id in await find_matching_cves(session, vendor, product, version):
                cve = await session.get(CVE, cve_id)
                if cve is None:
                    continue
                await create_finding(
                    session,
                    scan_id,
                    title=f"{cve_id} — {product}",
                    severity=cve.severity or Severity.info,
                    cve_id=cve_id,
                    risk_score=cve.cvss_score,
                    description=cve.description,
                )
                matched.append(cve_id)
    return matched


async def _run(scan_id: int, target: str, mode: str = "safe") -> str:
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as session:
            # Dış (public) web hedefine izin verildiyse iç-IP scope guard yerine
            # "yalnız-public" guard uygulanır (admin + açık onayla set edilir).
            scan = await get_scan(session, scan_id)
            external = bool(scan and scan.allow_external)
            want_dir_scan = bool(scan and scan.dir_scan)
            wordlist_id = scan.wordlist_id if scan else None
            parsed = urlparse(target if "://" in target else f"http://{target}")
            host = parsed.hostname or target
            port = parsed.port or (443 if parsed.scheme == "https" else 80)

            try:
                ip = await asyncio.to_thread(socket.gethostbyname, host)
                # Çözülen IP'yi scan'e yaz (rapor/canlı görünüm taranan host'u gösterir,
                # iç envanteri değil). Sonraki set_scan_status commit'i kalıcılaştırır.
                if scan is not None:
                    scan.resolved_ip = ip
                if external:
                    await validate_external_web_target(session, ip)
                else:
                    await validate_target(session, ip)
            except ScopeError as exc:
                await set_scan_status(session, scan_id, ScanStatus.failed, reason=str(exc))
                await log_action(session, "web_scan_denied", target=target)
                return "scope_denied"
            except OSError:
                await set_scan_status(
                    session, scan_id, ScanStatus.failed, reason="Hedef adı çözümlenemedi (DNS)."
                )
                return "resolve_error"

            await set_scan_status(session, scan_id, ScanStatus.running)
            # Canlı ilerleme/faz (web taraması da % gösterir — eskiden %0'da takılıyordu).
            await set_scan_progress(session, scan_id, 15, phase="Pasif web denetimi")
            # #12: İstekleri DOĞRULANAN ip'ye pinle — doğrulanan ve bağlanılan adres özdeş olur.
            url = pinned_url(target, ip)
            findings: list[WebFinding] = []
            # --- Pasif derinlik (her zaman; düşük risk, sadece yanıt analizi) ---
            page = await fetch_page(url)
            if page is not None:
                findings.extend(check_security_headers(page.headers))
                findings.extend(check_cookie_flags(page.set_cookie))
                findings.extend(check_cors(page.headers))
                findings.extend(check_info_disclosure(page.headers))
                # Web yığını CVE tespiti (banner→CVE; TÜM web modlarında — güvenli çıkarım, SR-3a).
                # Bulgular doğrudan DB'ye yazılır (WebFinding değil); raporda exploit görünür.
                with contextlib.suppress(Exception):
                    web_cves = await _web_cve_findings(
                        session, scan_id, ip, port, parsed.scheme or "http", page.headers
                    )
                    if web_cves:
                        uniq = list(set(web_cves))
                        await enrich_cves(session, uniq)
                        await apply_risk_scores(session, uniq)
            await set_scan_progress(session, scan_id, 45, phase="Hassas yol taraması")
            findings.extend(await check_common_paths(url))
            # Dizin/içerik keşfi (ayrı kutucuk; moddan bağımsız — gobuster benzeri kelime listesi).
            if want_dir_scan:
                await set_scan_progress(session, scan_id, 60, phase="Dizin/içerik keşfi")
                # Özel kelime listesi seçildiyse onun satırlarını kullan; yoksa yerleşik liste.
                words: list[str] | None = None
                if wordlist_id is not None:
                    wl = await get_wordlist(session, wordlist_id)
                    if wl is not None and wl.entries:
                        words = list(wl.entries)
                findings.extend(await directory_scan(url, words=words))
            if parsed.scheme == "https":
                # TLS denetimini de doğrulanan ip'ye bağla (yeniden çözüm/rebinding yok).
                await set_scan_progress(session, scan_id, 70, phase="TLS/sertifika denetimi")
                findings.extend(await asyncio.to_thread(check_tls, ip, port))
            # --- Aktif DAST (yalnız agresif + ack; müdahaleci payload gönderir) ---
            if is_aggressive(parse_mode(mode)):
                await set_scan_progress(session, scan_id, 85, phase="Aktif DAST testleri")
                findings.extend(await active_dast(url))

            await set_scan_progress(session, scan_id, 95, phase="Bulgular kaydediliyor")
            for finding in findings:
                await create_finding(
                    session,
                    scan_id,
                    finding.title,
                    severity=finding.severity,
                    description=finding.description,
                )
            # --- Web sömürü (YALNIZ Sömürme modu): tespit edilen web-yığını CVE'lerine MSF +
            # Exploit-DB uygular (SR-3b). Kapsam içi host SR-3a'da first-class asset olduğundan
            # collect_cve_targets hedefleri bulur. Kapılar: does_exploitation + msfrpcd/kill-switch
            # (+ çağıran uçta admin + ack + ALLOW_AGGRESSIVE). Aktif DAST'ın kendisi de web sömürüsü
            # (gerçek payload); bu adım ek olarak CVE-eşli exploit'leri dener. ---
            # LİSANS KAPISI: ``exploit`` sömürüsü için geçerli ticari lisans GEREKİR — eklenti
            # kurulu olsa bile lisans yoksa sömürü fazı hiç başlamaz (web tespiti tam sürer).
            from cybersectool.core.licensing import feature_licensed

            if does_exploitation(parse_mode(mode)) and await feature_licensed(session, "exploit"):
                created_by = scan.created_by if scan is not None else None
                # Sömürü eklentisi (opsiyonel): yoksa web tespiti tam, yalnız sömürü atlanır.
                try:
                    from cybersectool.exploit import msf_client
                    from cybersectool.exploit.exploitdb_stage import stage_exploitdb_attempts
                    from cybersectool.exploit.runner import run_exploitation_for_scan
                except ImportError:
                    pass
                else:
                    if msf_client.msf_configured():
                        await set_scan_progress(
                            session, scan_id, 97, phase="Web sömürü (Metasploit)"
                        )
                        with contextlib.suppress(Exception):
                            await run_exploitation_for_scan(session, scan_id, user_id=created_by)
                    await set_scan_progress(session, scan_id, 98, phase="Exploit-DB PoC eşleştirme")
                    with contextlib.suppress(Exception):
                        await stage_exploitdb_attempts(session, scan_id, user_id=created_by)
            # Kimliksiz uyum (roadmap #E): web taramasının TLS/HSTS bulgularından TLS + HTTP
            # uyum sonuçlarını türet → mevcut ComplianceCheck tablosuna sakla (kimlik gerekmez).
            # tls_checked=True: web taraması check_tls'i GERÇEKTEN çalıştırır → TLS denetlenmiştir.
            # Best-effort: hata web taramasını bozmaz.
            with contextlib.suppress(Exception):
                cl_results = await run_credentialless_compliance(session, scan_id, tls_checked=True)
                if cl_results:
                    await store_compliance(session, scan_id, cl_results)
            await notify_if_critical(session, scan_id, target)
            await set_scan_status(session, scan_id, ScanStatus.completed)
            await set_scan_progress(session, scan_id, 100, phase="Tamamlandı")
            await log_action(session, "web_scan", target=f"{target} ({len(findings)} bulgu)")
            return f"completed:{len(findings)}"
    finally:
        await engine.dispose()


async def _mark_failed(scan_id: int, target: str, reason: str) -> None:
    """Beklenmeyen hata → web taramasını 'başarısız' işaretle (sonsuza dek 'running' kalmasın).

    network/ping görevleriyle aynı kalkan: ``_run`` ``running`` yazdıktan sonra yakalanmayan
    bir hata fırlatırsa görev ``FAILURE`` olur ama DB durumu ``running``'de kalır, kurtarma yok.
    Ayrı bir oturumda durum=failed + neden bulgusu yazılır.
    """
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    try:
        factory = async_sessionmaker(engine, expire_on_commit=False)
        async with factory() as session:
            await set_scan_status(session, scan_id, ScanStatus.failed, reason=reason)
            with contextlib.suppress(Exception):
                await create_finding(
                    session,
                    scan_id,
                    title="Web taraması başarısız",
                    severity=Severity.info,
                    description=f"{target}: {reason}"[:500],
                )
    finally:
        await engine.dispose()


@celery_app.task(name="web_scan")
def web_scan_task(scan_id: int, target: str, mode: str = "safe") -> str:
    try:
        return asyncio.run(_run(scan_id, target, mode))
    except Exception as exc:  # işleme hatası → tarama 'başarısız' (takılı 'running' kalmaz)
        with contextlib.suppress(Exception):
            asyncio.run(_mark_failed(scan_id, target, str(exc)))
        return "failed"
