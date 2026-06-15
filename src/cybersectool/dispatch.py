"""Uygulama-seviyesi tarama dağıtımı (core + tasks orkestrasyonu).

Web ve API katmanlarının paylaştığı, bir zone'u tarayan yardımcı. Zone'daki her bloğu
scope guard'dan geçirir; izinli blokları ağ tarama kuyruğuna alır, kapsam dışı blokları
atlar. Mod (güvenli/agresif) gating'i çağıran uçta yapılır.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
from dataclasses import dataclass, field

import aiomysql
import asyncpg
import asyncssh
import oracledb
import pytds
from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.core.assets import list_assets
from cybersectool.core.audit import log_action
from cybersectool.core.credentials import get_secret
from cybersectool.core.findings import create_finding
from cybersectool.core.models import (
    Credential,
    CredentialType,
    Scan,
    ScanMode,
    ScanStatus,
    ScanType,
    Severity,
    Zone,
)
from cybersectool.core.notify import notify_if_critical
from cybersectool.core.scan_policy import is_aggressive
from cybersectool.core.scans import create_scan, set_scan_status
from cybersectool.core.scope import ScopeError, validate_target
from cybersectool.core.snmp_wordlist import SNMP_COMMUNITY_WORDLIST
from cybersectool.scanners.cisco_ios_audit import (
    CiscoIosAuditError,
    audit_cisco_ios,
    store_cisco_ios_audit,
)
from cybersectool.scanners.credentialed import run_credentialed_scan, store_credentialed
from cybersectool.scanners.db_audit import (
    audit_mssql,
    audit_mysql,
    audit_oracle,
    audit_postgres,
    store_db_audit,
)
from cybersectool.scanners.esxi_audit import EsxiAuditError, audit_esxi_https, store_esxi_audit
from cybersectool.scanners.ldap_audit import LdapAuditError, audit_ldap, store_ldap_audit
from cybersectool.scanners.smb_audit import SmbAuditError, audit_smb, store_smb_audit
from cybersectool.scanners.snmp import audit_snmp, store_snmp_audit
from cybersectool.scanners.telnet_audit import (
    TelnetAuditError,
    audit_telnet,
    store_telnet_audit,
)
from cybersectool.scanners.winrm import (
    WINRM_PORT,
    WinRMScanError,
    run_winrm_scan,
    store_winrm,
)
from cybersectool.tasks.network_scan import network_scan_task
from cybersectool.tasks.ping_scan import ping_scan_task


@dataclass
class ZoneScanResult:
    scans: list[Scan] = field(default_factory=list)
    scanned: list[str] = field(default_factory=list)  # kuyruğa alınan (in-scope) bloklar
    skipped: list[str] = field(default_factory=list)  # kapsam dışı (atlanan) bloklar


async def dispatch_target_list_scan(
    session: AsyncSession,
    targets: list[str],
    mode: ScanMode,
    user_id: int | None,
    label: str = "hızlı",
    categories: list[str] | None = None,
    batch_id: int | None = None,
    scan_type: ScanType = ScanType.network,
    ports: str | None = None,
    include_udp: bool = False,
) -> ZoneScanResult:
    """Bir hedef listesindeki her izinli IP/blok için ağ taraması başlatır; kapsam dışı atlar.

    Hem kayıtlı zone taraması hem de zone'suz hızlı tarama bunu kullanır. ``scan_type``
    ``vuln`` ise ağ taraması + derin CVE eşleştirme (KEV/EPSS) yapılır. ``ports`` port
    seçimini (None=genel, "all"=tüm, "80,443"=liste) tarama kaydına işler. ``include_udp``
    açıksa nmap'e hedeflenmiş UDP servis taraması (-sU) eklenir (#143).
    """
    result = ZoneScanResult()
    allowed: list[str] = []
    for cidr in targets:
        try:
            await validate_target(session, cidr)
        except ScopeError:
            result.skipped.append(cidr)
            continue
        allowed.append(cidr)
    if not allowed:
        return result
    # TÜM izinli blokları TEK taramada birleştir (zone seçince tek tarama; nmap çok
    # hedefi tek koşuda tarar). Bir zone'un N IP'si artık N ayrı tarama açmaz.
    combined = " ".join(allowed)
    display = combined if len(combined) <= 255 else f"{allowed[0]} (+{len(allowed) - 1} blok)"
    scan = await create_scan(
        session,
        scan_type,
        display,
        created_by=user_id,
        mode=mode,
        categories=categories,
        batch_id=batch_id,
        ports=ports,
        include_udp=include_udp,
    )
    action = "aggressive_scan_start" if is_aggressive(mode) else "scan_start"
    await log_action(
        session, action, user_id=user_id, target=f"{label}: {len(allowed)} blok [{mode}]"
    )
    async_result = network_scan_task.delay(scan.id, combined, str(mode))
    # Celery görev kimliğini sakla (kullanıcı durdurursa revoke için).
    task_id = getattr(async_result, "id", None)
    if task_id:
        scan.task_id = task_id
        await session.commit()
    result.scans.append(scan)
    result.scanned.extend(allowed)  # mesaj/sayım için bloklar; tarama tektir
    return result


async def dispatch_ping_scan(
    session: AsyncSession,
    targets: list[str],
    user_id: int | None,
    label: str = "hızlı",
    batch_id: int | None = None,
) -> ZoneScanResult:
    """Bir hedef listesindeki her izinli IP/blok için ping taraması (host keşfi) başlatır.

    Port taraması YAPILMAZ (nmap -sn) — yalnız ayakta hostlar bulunur ve envantere yazılır.
    Kapsam dışı bloklar atlanır. Mod kavramı yoktur (keşif tek tip, müdahaleci değil).
    """
    result = ZoneScanResult()
    allowed: list[str] = []
    for cidr in targets:
        try:
            await validate_target(session, cidr)
        except ScopeError:
            result.skipped.append(cidr)
            continue
        allowed.append(cidr)
    if not allowed:
        return result
    # TÜM izinli bloklar TEK ping taramasında birleştirilir (zone=tek tarama).
    combined = " ".join(allowed)
    display = combined if len(combined) <= 255 else f"{allowed[0]} (+{len(allowed) - 1} blok)"
    scan = await create_scan(
        session,
        ScanType.ping,
        display,
        created_by=user_id,
        mode=ScanMode.safe,
        batch_id=batch_id,
    )
    await log_action(
        session, "ping_scan_start", user_id=user_id, target=f"{label}: {len(allowed)} blok"
    )
    async_result = ping_scan_task.delay(scan.id, combined)
    task_id = getattr(async_result, "id", None)
    if task_id:
        scan.task_id = task_id
        await session.commit()
    result.scans.append(scan)
    result.scanned.extend(allowed)
    return result


async def dispatch_zone_scan(
    session: AsyncSession, zone: Zone, mode: ScanMode, user_id: int | None
) -> ZoneScanResult:
    """Zone'daki her izinli blok için ağ taraması (güvenli/agresif) başlatır; kapsam dışı atlar."""
    return await dispatch_target_list_scan(
        session, zone.cidrs, mode, user_id, label=f"zone:{zone.name}"
    )


async def dispatch_zones_scan(
    session: AsyncSession, zones: list[Zone], mode: ScanMode, user_id: int | None
) -> ZoneScanResult:
    """Birden çok IP zone'u tek seferde tarar; sonuçları (scanned/skipped) birleştirir."""
    agg = ZoneScanResult()
    for zone in zones:
        result = await dispatch_zone_scan(session, zone, mode, user_id)
        agg.scans.extend(result.scans)
        agg.scanned.extend(result.scanned)
        agg.skipped.extend(result.skipped)
    return agg


@dataclass
class ZoneCredentialedResult:
    scanned: list[str] = field(default_factory=list)  # başarıyla taranan host'lar
    skipped: list[str] = field(default_factory=list)  # kapsam dışı (atlanan)
    failed: list[str] = field(default_factory=list)  # hiçbir yöntem (SSH/WinRM) tutmadı
    methods: dict[str, str] = field(default_factory=dict)  # host -> "SSH" | "WinRM"


async def dispatch_inline_credentialed(
    session: AsyncSession,
    hosts: list[str],
    port: int,
    username: str,
    password: str,
    user_id: int | None,
    *,
    label: str = "kimlikli",
) -> ZoneCredentialedResult:
    """Her izinli host'a aynı kullanıcı/parola ile OS-öncelikli kimlikli denetim yapar.

    Açık porta göre — diğer taramalar gibi — **SSH** (Linux) ya da **WinRM/NTLM**
    (Windows) denenir. Kimlik bilgileri tüm host'lar için aynıdır, yalnızca anlık
    kullanılır, hiçbir yere saklanmaz. Girdiler tekil **host** olmalıdır.
    """
    result = ZoneCredentialedResult()
    for host in hosts:
        try:
            await validate_target(session, host)
        except ScopeError:
            result.skipped.append(host)
            continue

        ssh_open = await _port_open(host, port)
        win_open = await _any_windows_port_open(host)

        scan = await create_scan(session, ScanType.credentialed, host, created_by=user_id)
        await log_action(
            session, "credentialed_scan_start", user_id=user_id, target=f"{host} [{label}]"
        )
        await set_scan_status(session, scan.id, ScanStatus.running)

        method: str | None = None
        # OS önceliği: SSH portu açıksa SSH ile içeriden denetim.
        if ssh_open:
            try:
                facts, findings = await run_credentialed_scan(host, port, username, password)
            except (OSError, asyncssh.Error):
                pass
            else:
                await store_credentialed(session, scan.id, facts, findings)
                method = "SSH"
        # SSH tutmadıysa ve Windows portu açıksa WinRM (NTLM) ile denetim.
        if method is None and win_open:
            try:
                wfacts, wfindings = await run_winrm_scan(host, WINRM_PORT, username, password)
            except (OSError, WinRMScanError):
                pass
            else:
                await store_winrm(session, scan.id, wfacts, wfindings)
                method = "WinRM"

        if method:
            result.methods[host] = method
            result.scanned.append(host)
            await notify_if_critical(session, scan.id, host)
            await set_scan_status(session, scan.id, ScanStatus.completed)
        else:
            await set_scan_status(session, scan.id, ScanStatus.failed)
            result.failed.append(host)
    return result


async def dispatch_zone_credentialed(
    session: AsyncSession,
    zone: Zone,
    port: int,
    username: str,
    password: str,
    user_id: int | None,
) -> ZoneCredentialedResult:
    """Zone'daki her izinli host'a OS-öncelikli (SSH/WinRM) kimlikli denetim yapar."""
    return await dispatch_inline_credentialed(
        session, zone.cidrs, port, username, password, user_id, label=f"zone:{zone.name}"
    )


# --- IP zone × kimlik bölgesi taraması (OS öncelikli kimlik denemesi) ---

SSH_PORT = 22
WINDOWS_PORTS = (3389, 5985, 5986)  # RDP, WinRM HTTP, WinRM HTTPS


async def _any_windows_port_open(host: str) -> bool:
    """Host'ta herhangi bir Windows portu (RDP/WinRM) açık mı?"""
    for p in WINDOWS_PORTS:
        if await _port_open(host, p):
            return True
    return False


@dataclass
class CredZoneScanResult:
    matched: dict[str, str] = field(default_factory=dict)  # host -> başarılı kimlik (SSH/WinRM)
    windows_reachable: list[str] = field(default_factory=list)  # Win portu açık ama kimlik tutmadı
    skipped: list[str] = field(default_factory=list)  # kapsam dışı
    failed: list[str] = field(default_factory=list)  # hiçbir kimlik tutmadı / erişilemez


def _winrm_priority(creds: list[Credential]) -> list[Credential]:
    """WinRM denemesinde 'winrm' tipi kimlikleri öne alır (rdp tipi de denenir)."""
    return sorted(creds, key=lambda c: 0 if c.cred_type == CredentialType.winrm else 1)


def _winrm_username(cred: Credential) -> str:
    """Domain varsa DOMAIN\\user, yoksa düz kullanıcı adı (NTLM)."""
    if cred.domain:
        return f"{cred.domain}\\{cred.username}"
    return cred.username


async def _port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    """Host:port'a TCP bağlantı denemesi (OS ipucu için)."""
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        writer.close()
        with contextlib.suppress(OSError, asyncssh.Error):
            await writer.wait_closed()
        return True
    except (TimeoutError, OSError):
        return False


async def dispatch_credential_zone_scan(
    session: AsyncSession,
    ip_zone: Zone,
    credentials: list[Credential],
    user_id: int | None,
    categories: list[str] | None = None,
    batch_id: int | None = None,
    attempt_privesc: bool = False,
) -> CredZoneScanResult:
    """IP zone'daki her host'a kimlik bölgesindeki kimlikleri OS önceliğiyle dener.

    OS ipucu açık porttan çıkarılır: 22→Linux/SSH, 3389/5985/5986→Windows. Linux
    host'larda **SSH** ile, Windows host'larda **WinRM (NTLM)** ile salt-okunur
    kimlikli denetim yapılır; ikisi de tutmazsa host 'failed' olur. Kimlik bilgileri
    yalnızca anlık çözülür, hiçbir yere saklanmaz.

    ``attempt_privesc=True`` (admin + açık onay) ise SSH host'larda ek olarak GERÇEK yetki
    yükseltme DENEMESİ yapılır (VIII-3b, gated); her host için audit'lenir.
    """
    result = CredZoneScanResult()
    ssh_creds = [c for c in credentials if c.cred_type == CredentialType.ssh]
    win_creds = [
        c for c in credentials if c.cred_type in (CredentialType.winrm, CredentialType.rdp)
    ]

    for target in ip_zone.cidrs:
        try:
            await validate_target(session, target)
        except ScopeError:
            result.skipped.append(target)
            continue

        ssh_open = await _port_open(target, SSH_PORT)
        win_open = False
        for p in WINDOWS_PORTS:
            if await _port_open(target, p):
                win_open = True
                break

        scan = await create_scan(
            session,
            ScanType.credentialed,
            target,
            created_by=user_id,
            categories=categories,
            batch_id=batch_id,
        )
        await log_action(
            session,
            "credential_zone_scan",
            user_id=user_id,
            target=f"{target} [ipzone:{ip_zone.name}]",
        )
        await set_scan_status(session, scan.id, ScanStatus.running)

        worked: str | None = None
        # OS önceliği: Linux portu (22) açıksa SSH kimliklerini sırayla dene.
        if ssh_open and ssh_creds:
            if attempt_privesc:
                await log_action(
                    session, "privesc_attempt", user_id=user_id, target=f"{target} [ssh]"
                )
            for cred in ssh_creds:
                try:
                    facts, findings = await run_credentialed_scan(
                        target,
                        cred.port or SSH_PORT,
                        cred.username,
                        get_secret(cred),
                        attempt_privesc=attempt_privesc,
                    )
                except (OSError, asyncssh.Error):
                    continue
                await store_credentialed(session, scan.id, facts, findings)
                worked = cred.name
                break

        # SSH tutmadıysa ve Windows portu açıksa WinRM kimliklerini sırayla dene.
        if worked is None and win_open and win_creds:
            for cred in _winrm_priority(win_creds):
                try:
                    wfacts, wfindings = await run_winrm_scan(
                        target, cred.port or WINRM_PORT, _winrm_username(cred), get_secret(cred)
                    )
                except (OSError, WinRMScanError):
                    continue
                await store_winrm(session, scan.id, wfacts, wfindings)
                worked = cred.name
                break

        if worked:
            result.matched[target] = worked
            await notify_if_critical(session, scan.id, target)
            await set_scan_status(session, scan.id, ScanStatus.completed)
        elif win_open:
            # Windows portu açık ama hiçbir kimlik tutmadı (yanlış parola/yetki vb.)
            await create_finding(
                session,
                scan.id,
                "Windows portu erişilebilir (WinRM/RDP) ama kimlikli denetim başarısız",
                severity=Severity.info,
                description="Port açık; sağlanan Windows kimlikleriyle WinRM oturumu kurulamadı.",
            )
            result.windows_reachable.append(target)
            await set_scan_status(session, scan.id, ScanStatus.completed)
        else:
            await set_scan_status(session, scan.id, ScanStatus.failed)
            result.failed.append(target)

    return result


async def audit_credentialed_to_scan(
    session: AsyncSession,
    scan_id: int,
    hosts: list[str],
    credentials: list[Credential],
    *,
    attempt_privesc: bool = False,
    user_id: int | None = None,
) -> CredZoneScanResult:
    """NESSUS modeli: VAR OLAN bir taramaya (scan_id) içeriden kimlikli denetim EKLER.

    Yeni tarama/batch OLUŞTURMAZ ve durum değiştirmez (asıl teknik tarama worker'da sürer);
    bulgular aynı scan_id'ye asset bazında yazılır → kullanıcı TEK tarama görür. Her host'a
    OS-öncelikli SSH/WinRM kimlikli denetim yapılır. ``attempt_privesc`` (admin + açık onay,
    çağıran uçta) → SSH'te gerçek yetki yükseltme DENEMESİ. Kimlikler anlık çözülür, saklanmaz.
    """
    result = CredZoneScanResult()
    ssh_creds = [c for c in credentials if c.cred_type == CredentialType.ssh]
    win_creds = [
        c for c in credentials if c.cred_type in (CredentialType.winrm, CredentialType.rdp)
    ]
    assets_by_ip = {a.ip: a.id for a in await list_assets(session)}
    for target in hosts:
        try:
            await validate_target(session, target)
        except ScopeError:
            result.skipped.append(target)
            continue
        asset_id = assets_by_ip.get(target)
        ssh_open = await _port_open(target, SSH_PORT)
        win_open = await _any_windows_port_open(target)

        worked: str | None = None
        if ssh_open and ssh_creds:
            if attempt_privesc:
                await log_action(
                    session, "privesc_attempt", user_id=user_id, target=f"{target} [ssh]"
                )
            for cred in ssh_creds:
                try:
                    facts, findings = await run_credentialed_scan(
                        target,
                        cred.port or SSH_PORT,
                        cred.username,
                        get_secret(cred),
                        attempt_privesc=attempt_privesc,
                    )
                except (OSError, asyncssh.Error):
                    continue
                await store_credentialed(session, scan_id, facts, findings, asset_id=asset_id)
                worked = cred.name
                break
        if worked is None and win_open and win_creds:
            for cred in _winrm_priority(win_creds):
                try:
                    wfacts, wfindings = await run_winrm_scan(
                        target, cred.port or WINRM_PORT, _winrm_username(cred), get_secret(cred)
                    )
                except (OSError, WinRMScanError):
                    continue
                await store_winrm(session, scan_id, wfacts, wfindings, asset_id=asset_id)
                worked = cred.name
                break

        if worked:
            result.matched[target] = worked
        elif win_open:
            result.windows_reachable.append(target)
        else:
            result.failed.append(target)
    return result


async def dispatch_credential_zones_scan(
    session: AsyncSession,
    ip_zones: list[Zone],
    credentials: list[Credential],
    user_id: int | None,
) -> CredZoneScanResult:
    """Birden çok IP zone'u aynı kimlik kümesiyle tarar; sonuçları birleştirir."""
    agg = CredZoneScanResult()
    for ip_zone in ip_zones:
        result = await dispatch_credential_zone_scan(session, ip_zone, credentials, user_id)
        agg.matched.update(result.matched)
        agg.windows_reachable.extend(result.windows_reachable)
        agg.skipped.extend(result.skipped)
        agg.failed.extend(result.failed)
    return agg


# --- Denetim panelleri (DB/SNMP/SMB/LDAP/Telnet) için IP zone → host genişletme (X-3) ---


async def assets_in_zones(session: AsyncSession, zone_ids: list[int]) -> list[str]:
    """Seçilen IP zone'ların CIDR'lerine düşen AYAKTA envanter varlıklarının IP'leri.

    Denetim panellerinde (DB/SNMP/SMB/LDAP/Telnet) IP zone seçimi /24'ü 254 host'a açmaz;
    yalnızca envanterde KAYITLI ve ``is_up`` (ayakta doğrulanmış) varlıklardan zone'a düşenler
    hedeflenir. Sıra korunur, IP tekrarları elenir. Yetkilendirme yine scope guard'a tabidir
    (her host per-host dispatch içinde ``validate_target``'tan geçer).
    """
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for zid in zone_ids:
        zone = await session.get(Zone, zid)
        if zone is None:
            continue
        for cidr in zone.cidrs:
            with contextlib.suppress(ValueError):
                nets.append(ipaddress.ip_network(cidr, strict=False))
    if not nets:
        return []
    ips: list[str] = []
    seen: set[str] = set()
    for asset in await list_assets(session):
        # URL varlıkları (ip=NULL) IP-zone host genişlemesine katılmaz.
        if not asset.is_up or asset.ip is None or asset.ip in seen:
            continue
        try:
            addr = ipaddress.ip_address(asset.ip)
        except ValueError:
            continue
        if any(addr in net for net in nets):
            seen.add(asset.ip)
            ips.append(asset.ip)
    return ips


async def dispatch_db_audit(
    session: AsyncSession,
    host: str,
    port: int,
    credential: Credential,
    database: str,
    user_id: int | None,
    batch_id: int | None = None,
    *,
    engine: str = "postgres",
) -> Scan:
    """DB'ye salt-okunur kimlikli config denetimi (VII-2a / IX-4). Kapsam-korumalı, satır-içi.

    ``engine``: 'postgres' | 'mysql'. Hedef host scope guard'dan geçer; kimlik anlık
    çözülür (saklanmaz). Sonuç + CIS uyumu Finding/ComplianceCheck olarak yazılır.
    """
    scan = await create_scan(
        session,
        ScanType.credentialed,
        f"{host}:{port}/{database or '-'} [{engine}]",
        created_by=user_id,
        batch_id=batch_id,
    )
    await log_action(
        session, "db_audit", user_id=user_id, target=f"{host}:{port}/{database} [{engine}]"
    )
    try:
        await validate_target(session, host)
    except ScopeError:
        await create_finding(
            session,
            scan.id,
            "Hedef kapsam dışı — DB denetimi atlandı",
            severity=Severity.info,
            description=f"{host} yetkili tarama kapsamında değil.",
        )
        await set_scan_status(session, scan.id, ScanStatus.failed)
        return scan
    await set_scan_status(session, scan.id, ScanStatus.running)
    secret = get_secret(credential)
    try:
        if engine == "mysql":
            version, findings = await audit_mysql(host, port, credential.username, secret, database)
        elif engine == "mssql":
            version, findings = await audit_mssql(host, port, credential.username, secret, database)
        elif engine == "oracle":
            version, findings = await audit_oracle(
                host, port, credential.username, secret, database
            )
        else:
            version, findings = await audit_postgres(
                host, port, credential.username, secret, database or "postgres"
            )
    except (
        TimeoutError,
        OSError,
        asyncpg.PostgresError,
        aiomysql.Error,
        pytds.Error,
        oracledb.Error,
    ) as exc:
        await create_finding(
            session,
            scan.id,
            "DB bağlantı/denetim başarısız",
            severity=Severity.info,
            description=f"Bağlantı kurulamadı ya da kimlik tutmadı: {exc}",
        )
        await set_scan_status(session, scan.id, ScanStatus.failed)
        return scan
    await store_db_audit(session, scan.id, version, findings, engine=engine)
    await notify_if_critical(session, scan.id, host)
    await set_scan_status(session, scan.id, ScanStatus.completed)
    return scan


async def dispatch_smb_audit(
    session: AsyncSession,
    host: str,
    port: int,
    *,
    credential: Credential | None,
    user_id: int | None,
    batch_id: int | None = None,
    share_names: list[str] | None = None,
) -> Scan:
    """SMB salt-okunur paylaşım/güvenlik denetimi (IX-7a). Kapsam-korumalı, satır-içi.

    Hedef host scope guard'dan geçer. Kimlik OPSİYONELDİR: verilmezse anonim denetim
    yapılır (null/guest/imza/SMBv1 yine tespit edilir); verilirse kimlik anlık çözülür
    (saklanmaz) ve yetkili paylaşım envanteri eklenir. Hedefe YAZMAZ (ENUM + login denemesi).
    """
    scan = await create_scan(
        session,
        ScanType.credentialed,
        f"{host}:{port} [smb]",
        created_by=user_id,
        batch_id=batch_id,
    )
    await log_action(session, "smb_audit", user_id=user_id, target=f"{host}:{port}")
    try:
        await validate_target(session, host)
    except ScopeError:
        await create_finding(
            session,
            scan.id,
            "Hedef kapsam dışı — SMB denetimi atlandı",
            severity=Severity.info,
            description=f"{host} yetkili tarama kapsamında değil.",
        )
        await set_scan_status(session, scan.id, ScanStatus.failed)
        return scan
    await set_scan_status(session, scan.id, ScanStatus.running)
    username = password = domain = ""
    if credential is not None:
        username = credential.username
        password = get_secret(credential)
        domain = credential.domain or ""
    try:
        info, findings = await audit_smb(
            host, port, user=username, password=password, domain=domain, share_names=share_names
        )
    except (TimeoutError, OSError, SmbAuditError) as exc:
        await create_finding(
            session,
            scan.id,
            "SMB denetimi başarısız",
            severity=Severity.info,
            description=f"SMB erişimi kurulamadı: {exc}",
        )
        await set_scan_status(session, scan.id, ScanStatus.failed)
        return scan
    await store_smb_audit(session, scan.id, info, findings)
    await notify_if_critical(session, scan.id, host)
    await set_scan_status(session, scan.id, ScanStatus.completed)
    return scan


async def dispatch_ldap_audit(
    session: AsyncSession,
    host: str,
    port: int,
    *,
    credential: Credential | None,
    user_id: int | None,
    batch_id: int | None = None,
) -> Scan:
    """LDAP/AD salt-okunur güvenlik denetimi (IX-7b). Kapsam-korumalı, satır-içi.

    Hedef host scope guard'dan geçer. Kimlik OPSİYONELDİR: verilmezse anonim denetim
    yapılır (anonim bind/okuma + şifreleme yine tespit edilir); verilirse kimlik anlık
    çözülür (saklanmaz) ve AD parola politikası best-effort okunur. Hedefe YAZMAZ.
    """
    scan = await create_scan(
        session,
        ScanType.credentialed,
        f"{host}:{port} [ldap]",
        created_by=user_id,
        batch_id=batch_id,
    )
    await log_action(session, "ldap_audit", user_id=user_id, target=f"{host}:{port}")
    try:
        await validate_target(session, host)
    except ScopeError:
        await create_finding(
            session,
            scan.id,
            "Hedef kapsam dışı — LDAP denetimi atlandı",
            severity=Severity.info,
            description=f"{host} yetkili tarama kapsamında değil.",
        )
        await set_scan_status(session, scan.id, ScanStatus.failed)
        return scan
    await set_scan_status(session, scan.id, ScanStatus.running)
    username = password = ""
    if credential is not None:
        username = credential.username
        password = get_secret(credential)
    try:
        info, findings = await audit_ldap(host, port, user=username, password=password)
    except (TimeoutError, OSError, LdapAuditError) as exc:
        await create_finding(
            session,
            scan.id,
            "LDAP denetimi başarısız",
            severity=Severity.info,
            description=f"LDAP erişimi kurulamadı: {exc}",
        )
        await set_scan_status(session, scan.id, ScanStatus.failed)
        return scan
    await store_ldap_audit(session, scan.id, info, findings)
    await notify_if_critical(session, scan.id, host)
    await set_scan_status(session, scan.id, ScanStatus.completed)
    return scan


async def dispatch_telnet_audit(
    session: AsyncSession,
    host: str,
    port: int,
    *,
    credential: Credential | None,
    user_id: int | None,
    batch_id: int | None = None,
) -> Scan:
    """Telnet/Cisco CLI salt-okunur güvenlik denetimi (IX-7c). Kapsam-korumalı, satır-içi.

    Hedef host scope guard'dan geçer. Kimlik OPSİYONELDİR: verilmezse Telnet açıklığı +
    banner yine tespit edilir; verilirse kimlik anlık çözülür (saklanmaz) ve salt-okunur
    'show running-config' ile Cisco sertleştirme denetlenir. Hedefe YAZMAZ.
    """
    scan = await create_scan(
        session,
        ScanType.credentialed,
        f"{host}:{port} [telnet]",
        created_by=user_id,
        batch_id=batch_id,
    )
    await log_action(session, "telnet_audit", user_id=user_id, target=f"{host}:{port}")
    try:
        await validate_target(session, host)
    except ScopeError:
        await create_finding(
            session,
            scan.id,
            "Hedef kapsam dışı — Telnet denetimi atlandı",
            severity=Severity.info,
            description=f"{host} yetkili tarama kapsamında değil.",
        )
        await set_scan_status(session, scan.id, ScanStatus.failed)
        return scan
    await set_scan_status(session, scan.id, ScanStatus.running)
    username = password = ""
    if credential is not None:
        username = credential.username
        password = get_secret(credential)
    try:
        info, findings = await audit_telnet(host, port, user=username, password=password)
    except (TimeoutError, OSError, TelnetAuditError) as exc:
        await create_finding(
            session,
            scan.id,
            "Telnet denetimi başarısız",
            severity=Severity.info,
            description=f"Telnet erişimi kurulamadı: {exc}",
        )
        await set_scan_status(session, scan.id, ScanStatus.failed)
        return scan
    await store_telnet_audit(session, scan.id, info, findings)
    await notify_if_critical(session, scan.id, host)
    await set_scan_status(session, scan.id, ScanStatus.completed)
    return scan


async def dispatch_cisco_ios_audit(
    session: AsyncSession,
    host: str,
    port: int,
    *,
    credential: Credential | None,
    user_id: int | None,
    batch_id: int | None = None,
) -> Scan:
    """Cisco IOS SSH salt-okunur sertleştirme denetimi (VII-2d). Kapsam-korumalı, satır-içi.

    Telnet denetiminin (IX-7c) aksine kimlik ZORUNLUDUR: SSH ile giriş yapılıp salt-okunur
    'show running-config' okunur (Telnet kapalı / SSH-only cihazları kapsar). Kimlik anlık
    çözülür (saklanmaz). Hedefe YAZMAZ.
    """
    scan = await create_scan(
        session,
        ScanType.credentialed,
        f"{host}:{port} [cisco-ios-ssh]",
        created_by=user_id,
        batch_id=batch_id,
    )
    await log_action(session, "cisco_ios_audit", user_id=user_id, target=f"{host}:{port}")
    try:
        await validate_target(session, host)
    except ScopeError:
        await create_finding(
            session,
            scan.id,
            "Hedef kapsam dışı — Cisco IOS SSH denetimi atlandı",
            severity=Severity.info,
            description=f"{host} yetkili tarama kapsamında değil.",
        )
        await set_scan_status(session, scan.id, ScanStatus.failed)
        return scan
    if credential is None:
        await create_finding(
            session,
            scan.id,
            "Cisco IOS SSH denetimi — kimlik gerekli",
            severity=Severity.info,
            description=(
                "SSH kimliği olmadan 'show running-config' okunamaz; bir SSH kimliği seçin."
            ),
        )
        await set_scan_status(session, scan.id, ScanStatus.failed)
        return scan
    await set_scan_status(session, scan.id, ScanStatus.running)
    try:
        info, findings = await audit_cisco_ios(
            host, port, user=credential.username, password=get_secret(credential)
        )
    except (TimeoutError, OSError, CiscoIosAuditError) as exc:
        await create_finding(
            session,
            scan.id,
            "Cisco IOS SSH denetimi başarısız",
            severity=Severity.info,
            description=f"SSH erişimi kurulamadı: {exc}",
        )
        await set_scan_status(session, scan.id, ScanStatus.failed)
        return scan
    await store_cisco_ios_audit(session, scan.id, info, findings)
    await notify_if_critical(session, scan.id, host)
    await set_scan_status(session, scan.id, ScanStatus.completed)
    return scan


async def dispatch_esxi_audit(
    session: AsyncSession,
    host: str,
    port: int,
    *,
    user_id: int | None,
    batch_id: int | None = None,
) -> Scan:
    """VMware ESXi/vCenter kimliksiz HTTPS duruş denetimi (VII-2c). Kapsam-korumalı, satır-içi.

    Kimlik GEREKMEZ: 443 ucu kimliksiz yoklanır (welcome/sdk tanımı, sürüm ifşası, MOB
    açıklığı, TLS duruşu). Hedefe YAZMAZ (yalnız GET). Host scope guard'dan geçer.
    """
    scan = await create_scan(
        session,
        ScanType.credentialed,
        f"{host}:{port} [esxi]",
        created_by=user_id,
        batch_id=batch_id,
    )
    await log_action(session, "esxi_audit", user_id=user_id, target=f"{host}:{port}")
    try:
        await validate_target(session, host)
    except ScopeError:
        await create_finding(
            session,
            scan.id,
            "Hedef kapsam dışı — ESXi/vCenter denetimi atlandı",
            severity=Severity.info,
            description=f"{host} yetkili tarama kapsamında değil.",
        )
        await set_scan_status(session, scan.id, ScanStatus.failed)
        return scan
    await set_scan_status(session, scan.id, ScanStatus.running)
    try:
        info, findings = await audit_esxi_https(host, port)
    except (TimeoutError, OSError, EsxiAuditError) as exc:
        await create_finding(
            session,
            scan.id,
            "ESXi/vCenter denetimi başarısız",
            severity=Severity.info,
            description=f"HTTPS yönetim ucuna erişilemedi: {exc}",
        )
        await set_scan_status(session, scan.id, ScanStatus.failed)
        return scan
    await store_esxi_audit(session, scan.id, info, findings)
    await notify_if_critical(session, scan.id, host)
    await set_scan_status(session, scan.id, ScanStatus.completed)
    return scan


async def dispatch_esxi_audit_hosts(
    session: AsyncSession,
    hosts: list[str],
    port: int,
    *,
    user_id: int | None,
) -> list[Scan]:
    """Birden çok host'a ESXi/vCenter kimliksiz denetim; her host için ``dispatch_esxi_audit``."""
    return [await dispatch_esxi_audit(session, host, port, user_id=user_id) for host in hosts]


def first_cred_of_type(
    credentials: list[Credential], *cred_types: CredentialType
) -> Credential | None:
    """Listede verilen tip(ler)den İLK kimliği döndürür (yoksa None). Tipe uygun seçim (X-3)."""
    for cred in credentials:
        if cred.cred_type in cred_types:
            return cred
    return None


async def dispatch_db_audit_hosts(
    session: AsyncSession,
    hosts: list[str],
    port: int,
    credential: Credential,
    database: str,
    user_id: int | None,
    *,
    engine: str = "postgres",
) -> list[Scan]:
    """Birden çok host'a aynı DB kimliğiyle salt-okunur DB denetimi (X-3). Her host ayrı tarama.

    Per-host ``dispatch_db_audit`` çağrılır (denetim mantığı tek yerde; kapsam-koruması orada).
    """
    scans: list[Scan] = []
    for host in hosts:
        scans.append(
            await dispatch_db_audit(
                session, host, port, credential, database, user_id, engine=engine
            )
        )
    return scans


async def dispatch_snmp_audit_hosts(
    session: AsyncSession,
    hosts: list[str],
    port: int,
    *,
    credential: Credential | None,
    user_id: int | None,
    extra_communities: list[str] | None = None,
) -> list[Scan]:
    """Birden çok host'a SNMP denetimi (X-3); her host için per-host ``dispatch_snmp_audit``."""
    return [
        await dispatch_snmp_audit(
            session,
            host,
            port,
            credential=credential,
            user_id=user_id,
            extra_communities=extra_communities,
        )
        for host in hosts
    ]


async def dispatch_smb_audit_hosts(
    session: AsyncSession,
    hosts: list[str],
    port: int,
    *,
    credential: Credential | None,
    user_id: int | None,
    share_names: list[str] | None = None,
) -> list[Scan]:
    """Birden çok host'a SMB denetimi (X-3); her host için per-host ``dispatch_smb_audit``."""
    return [
        await dispatch_smb_audit(
            session, host, port, credential=credential, user_id=user_id, share_names=share_names
        )
        for host in hosts
    ]


async def dispatch_ldap_audit_hosts(
    session: AsyncSession,
    hosts: list[str],
    port: int,
    *,
    credential: Credential | None,
    user_id: int | None,
) -> list[Scan]:
    """Birden çok host'a LDAP denetimi (X-3); her host için per-host ``dispatch_ldap_audit``."""
    return [
        await dispatch_ldap_audit(session, host, port, credential=credential, user_id=user_id)
        for host in hosts
    ]


async def dispatch_telnet_audit_hosts(
    session: AsyncSession,
    hosts: list[str],
    port: int,
    *,
    credential: Credential | None,
    user_id: int | None,
) -> list[Scan]:
    """Birden çok host'a Telnet denetimi (X-3); her host için per-host ``dispatch_telnet_audit``."""
    return [
        await dispatch_telnet_audit(session, host, port, credential=credential, user_id=user_id)
        for host in hosts
    ]


async def dispatch_cisco_ios_audit_hosts(
    session: AsyncSession,
    hosts: list[str],
    port: int,
    *,
    credential: Credential | None,
    user_id: int | None,
) -> list[Scan]:
    """Birden çok host'a Cisco IOS SSH denetimi; her host için ``dispatch_cisco_ios_audit``."""
    return [
        await dispatch_cisco_ios_audit(session, host, port, credential=credential, user_id=user_id)
        for host in hosts
    ]


async def dispatch_snmp_audit(
    session: AsyncSession,
    host: str,
    port: int,
    *,
    credential: Credential | None,
    user_id: int | None,
    batch_id: int | None = None,
    extra_communities: list[str] | None = None,
) -> Scan:
    """SNMP salt-okunur envanter + zayıf-topluluk denetimi (VII-2b). Kapsam-korumalı.

    Hedef host scope guard'dan geçer. Dahili community wordlist'i v1 VE v2c ile
    (eşzamanlı) denenir; verilmişse özel topluluk da denenir (kimlik kasasından anlık
    çözülür, saklanmaz). Versiyon seçilmez — tutan sürüm+topluluk raporlanır. Yalnız
    GET (yazma yok). Envanter + bulgular Finding olarak yazılır.
    """
    scan = await create_scan(
        session,
        ScanType.credentialed,
        f"{host}:{port} [snmp]",
        created_by=user_id,
        batch_id=batch_id,
    )
    await log_action(session, "snmp_audit", user_id=user_id, target=f"{host}:{port}")
    try:
        await validate_target(session, host)
    except ScopeError:
        await create_finding(
            session,
            scan.id,
            "Hedef kapsam dışı — SNMP denetimi atlandı",
            severity=Severity.info,
            description=f"{host} yetkili tarama kapsamında değil.",
        )
        await set_scan_status(session, scan.id, ScanStatus.failed)
        return scan
    await set_scan_status(session, scan.id, ScanStatus.running)
    communities = list(SNMP_COMMUNITY_WORDLIST)
    # Kullanıcının seçtiği topluluk kelime listesi (snmp_community) — gömülü listeye eklenir.
    extra = [c.strip() for c in (extra_communities or []) if c.strip()]
    for community in extra:
        if community not in communities:
            communities.append(community)
    if credential is not None:
        custom = get_secret(credential).strip()
        # SNMP toplulukları büyük/küçük harf DUYARLIDIR; özel değer wordlist ile yalnız case
        # farklıysa (ör. 'Public') yine de denenmeli → wordlist.lower() yerine listeyle karşılaştır.
        if custom and custom not in communities:
            communities.append(custom)
    # Zayıf-sayılan topluluklar: gömülü liste + kullanıcı listesi (ikisi de tahmin edilebilir).
    weak = (*SNMP_COMMUNITY_WORDLIST, *extra)
    try:
        info, accessible, findings = await audit_snmp(
            host, port, communities=communities, weak_communities=weak
        )
    except (TimeoutError, OSError) as exc:
        await create_finding(
            session,
            scan.id,
            "SNMP denetimi başarısız",
            severity=Severity.info,
            description=f"SNMP erişimi kurulamadı: {exc}",
        )
        await set_scan_status(session, scan.id, ScanStatus.failed)
        return scan
    await store_snmp_audit(session, scan.id, info, accessible, findings)
    await notify_if_critical(session, scan.id, host)
    await set_scan_status(session, scan.id, ScanStatus.completed)
    return scan
