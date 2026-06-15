"""RPC/DCE-RPC zafiyet probe'u (#168 RPC-PROBE) — SALT-OKUNUR.

Bazı kritik Windows açıkları **versiyon banner'ı sızdırmaz** → aracın sürüm→CVE eşleştirmesi
bunları ASLA yakalayamaz. En önemlisi **PrintNightmare** (CVE-2021-1675 + CVE-2021-34527): Print
Spooler servisinin MS-RPRN (Print System Remote Protocol) RPC arayüzü üzerinden sömürülür; açık
bir port/sürüm olarak görünmez, yalnız RPC arayüzü erişilebilir olarak durur. Bu modül impacket
DCE/RPC ile bu arayüzün **uzaktan erişilebilir olup olmadığını** aktif olarak doğrular.

GÜVENLİK (DEĞİŞMEZ): bu bir TESPİT probe'udur, SÖMÜRÜ DEĞİL. Yalnız RPC arayüzüne **bind** eder
(``RpcAddPrinterDriverEx`` gibi sömürü primitifini ASLA çağırmaz) — hedefe hiçbir şey yazmaz,
sürücü eklemez, servisi düşürmez. ``exposed_services``/``smb_audit`` ile aynı salt-okunur sınıfta;
bu yüzden agresif kilide tabi DEĞİL, her tarama modunda çalışır (Güvenli CVE dahil).

ÖNEMLİ (dürüst raporlama): erişilebilirlik, **yamasızlığı KANITLAMAZ** — yamalı bir host'ta da
Spooler RPC arayüzü açık kalır. Bu yüzden bulgu "PrintNightmare ADAYI / saldırı yüzeyi açık —
yama seviyesini doğrulayın" diye raporlanır (``validated=False``), kesin-doğrulanmış değil.

``evaluate_rpc`` ve hata-sınıflandırma SAFtır (ağsız, birim testi edilebilir); ``_probe_*``
fonksiyonları impacket ile ağ erişimi yapar (gerçek bir Windows hedefine karşı doğrulanır).
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
from dataclasses import dataclass

from cybersectool.core.models import Severity

# RPC/SMB taşıma portları. MS-RPRN named pipe (``\pipe\spoolss``) SMB üzerinden (445, yoksa 139);
# endpoint mapper (rpcdump) TCP 135 üzerinden. nmap bu portları açık bulduğunda probe tetiklenir.
RPC_SMB_PORTS: tuple[int, ...] = (445, 139)
RPC_EPM_PORT = 135

# PrintNightmare çift-CVE'si (patron kanıtı: ikisi de hedefte mevcut ama sürüm-CVE olmadıkları için
# bulunamıyordu). İkisi de aynı Spooler/MS-RPRN saldırı yüzeyinden doğar → erişilebilirlik ikisini
# de aday yapar. Her biri ayrı bir bulgu olur ki Zafiyetler sayfasında ikisi de görünsün.
PRINTNIGHTMARE_CVES: tuple[str, ...] = ("CVE-2021-1675", "CVE-2021-34527")

# impacket hata mesajlarında "pipe var ama yetki gerekiyor" sinyalleri. Bu, Spooler arayüzünün
# MEVCUT olduğunu (erişilebilir) ama anonim bind'in reddedildiğini gösterir → yine de aday.
_ACCESS_DENIED_MARKERS: tuple[str, ...] = (
    "access_denied",
    "access denied",
    "rpc_s_access_denied",
    "0xc0000022",  # STATUS_ACCESS_DENIED
)


@dataclass
class RpcInfo:
    """Bir host'un RPC probe sonucu (salt-okunur tespit)."""

    spooler_reachable: bool = False
    # Erişilebilirlik nasıl doğrulandı: "bind" (anonim bind başarılı), "access_denied" (pipe var,
    # yetki gerekti) ya da "epm" (endpoint mapper'da MS-RPRN kayıtlı). Açıklamada gösterilir.
    spooler_confirm: str = ""
    reached_rpc: bool = False  # herhangi bir RPC bağlantısı kurulabildi mi (tanı için)


@dataclass
class RpcFinding:
    """RPC probe'undan üretilen bir zafiyet adayı bulgusu."""

    title: str
    severity: Severity
    detail: str
    cve_id: str | None = None


def _confirm_label(confirm: str) -> str:
    """``spooler_confirm`` kodunu insan-okunur Türkçe açıklamaya çevirir (SAF)."""
    return {
        "bind": "anonim RPC bind başarılı",
        "access_denied": "RPC arayüzü mevcut (bind için yetki gerekti)",
        "epm": "endpoint mapper'da (TCP 135) MS-RPRN kayıtlı",
    }.get(confirm, confirm or "erişilebilir")


def evaluate_rpc(info: RpcInfo) -> list[RpcFinding]:
    """RPC probe envanterinden bulguları üretir (SAF; ağ gerektirmez).

    Spooler RPC arayüzü uzaktan erişilebilirse PrintNightmare çift-CVE'sinin her biri için bir
    "saldırı yüzeyi açık / aday" bulgusu üretir. Erişilebilirlik aktif doğrulanır (bu yüzden
    raporlanır) ama yamasızlık kanıtlanmaz → ``validated=False`` (çağıran uçta), severity HIGH.
    """
    if not info.spooler_reachable:
        return []
    how = _confirm_label(info.spooler_confirm)
    findings: list[RpcFinding] = []
    for cve in PRINTNIGHTMARE_CVES:
        findings.append(
            RpcFinding(
                title=f"Print Spooler RPC erişilebilir — PrintNightmare adayı ({cve})",
                severity=Severity.high,
                cve_id=cve,
                detail=(
                    "Print Spooler servisinin MS-RPRN (Print System Remote Protocol) RPC "
                    f"arayüzü uzaktan erişilebilir durumda ({how}). Bu, PrintNightmare ({cve}) "
                    "için saldırı yüzeyinin AÇIK olduğunu gösterir: yama uygulanmamışsa kimlik "
                    "doğrulamış bir saldırgan RpcAddPrinterDriverEx ile SYSTEM olarak uzaktan kod "
                    "çalıştırabilir (Domain Controller'da domain ele geçirmeye kadar gider). Bu "
                    "bulgu ERİŞİLEBİLİRLİĞİ aktif doğrular ama yama seviyesini KANITLAMAZ — yamalı "
                    "host'ta da arayüz açık kalır; yüklü güncellemeleri teyit edin. Çözüm: Domain "
                    "Controller'larda Print Spooler'ı kapatın (Stop-Service Spooler; "
                    "Set-Service Spooler -StartupType Disabled) ve ilgili güvenlik yamalarını "
                    "uygulayın. Bu açık SÜRÜM banner'ı sızdırmadığından klasik CVE taraması "
                    "yakalayamaz — yalnız bu RPC probe'u tespit eder."
                ),
            )
        )
    return findings


# --- Ağ erişimi (impacket DCE/RPC) — senkron yardımcılar to_thread içinde çağrılır ---------------


def _is_access_denied(exc: Exception) -> bool:
    """impacket istisna mesajı 'pipe var ama yetki gerekti' diyor mu? (SAF — string sınıflandırma).

    ACCESS_DENIED, bağlantı reddinden FARKLIDIR: pipe/arayüz MEVCUTTUR, yalnız anonim bind
    reddedilmiştir → Spooler yine erişilebilir sayılır (aday). Bağlantı reddi/timeout ise
    erişilemez demektir (bu fonksiyon False döner → çağıran "erişilemez" sayar).
    """
    text = str(exc).lower()
    return any(marker in text for marker in _ACCESS_DENIED_MARKERS)


def _spooler_via_pipe(
    host: str, port: int, user: str, password: str, domain: str, timeout: float
) -> str:
    """``\\pipe\\spoolss`` üzerinden MS-RPRN arayüzüne bind dener (SMB 445/139, salt-okunur).

    Dönüş: ``"bind"`` (anonim bind başarılı), ``"access_denied"`` (pipe var, yetki gerekti) ya da
    ``""`` (erişilemez). Yalnız ``dce.bind`` çağrılır — sömürü primitifi (sürücü ekleme) ASLA
    çağrılmaz. Bağlantı/bind dışında hiçbir veri yazılmaz; bağlantı hemen kapatılır.
    """
    from impacket.dcerpc.v5 import rprn, transport

    stringbinding = rf"ncacn_np:{host}[\pipe\spoolss]"
    rpctransport = transport.DCERPCTransportFactory(stringbinding)
    with contextlib.suppress(Exception):
        rpctransport.set_connect_timeout(timeout)
    with contextlib.suppress(Exception):
        rpctransport.set_dport(port)
    with contextlib.suppress(Exception):
        # Anonim (null) oturum varsayılan; kimlik verilirse kullanılır (gelecekte kimlikli probe).
        rpctransport.set_credentials(user, password, domain)
    dce = rpctransport.get_dce_rpc()
    try:
        dce.connect()
    except Exception as exc:  # bağlantı kurulamadı (refused/timeout) ya da yetki reddi
        return "access_denied" if _is_access_denied(exc) else ""
    try:
        dce.bind(rprn.MSRPC_UUID_RPRN)
    except Exception as exc:  # arayüz yok / yetki reddi
        return "access_denied" if _is_access_denied(exc) else ""
    finally:
        with contextlib.suppress(Exception):
            dce.disconnect()
    return "bind"


def _spooler_via_epm(host: str, timeout: float) -> bool:
    """Endpoint mapper'a (TCP 135) MS-RPRN arayüzünün kayıtlı olup olmadığını sorar (rpcdump tarzı).

    ``\\pipe\\spoolss`` (445) filtreliyse ama 135 açıksa ikincil tespit yolu. ``epm.hept_map``
    arayüz kayıtlıysa bir string-binding döner, değilse istisna fırlatır. Kendi taşımasını 135'e
    açtığından (timeout parametresi yok) soket varsayılan timeout'u GEÇİCİ olarak ayarlanır ki
    filtreli bir 135 taramayı asmasın.
    """
    from impacket.dcerpc.v5 import epm, rprn

    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        binding = epm.hept_map(host, rprn.MSRPC_UUID_RPRN, protocol="ncacn_ip_tcp")
        return bool(binding)
    except Exception:  # arayüz kayıtlı değil / 135 erişilemez
        return False
    finally:
        socket.setdefaulttimeout(old)


def _probe_rpc(
    host: str,
    smb_port: int | None,
    epm_open: bool,
    user: str,
    password: str,
    domain: str,
    timeout: float,
) -> RpcInfo:
    """RPC arayüz erişilebilirliğini salt-okunur denetler (senkron; to_thread içinde çağrılır)."""
    info = RpcInfo()
    if smb_port:
        confirm = _spooler_via_pipe(host, smb_port, user, password, domain, timeout)
        if confirm:
            info.spooler_reachable = True
            info.spooler_confirm = confirm
            info.reached_rpc = True
    # Pipe yolu doğrulayamadıysa ve 135 açıksa endpoint mapper'dan teyit dene.
    if not info.spooler_reachable and epm_open and _spooler_via_epm(host, timeout):
        info.spooler_reachable = True
        info.spooler_confirm = "epm"
        info.reached_rpc = True
    return info


async def audit_rpc(
    host: str,
    *,
    smb_port: int | None = 445,
    epm_open: bool = False,
    user: str = "",
    password: str = "",
    domain: str = "",
    timeout: float = 8.0,
) -> tuple[RpcInfo, list[RpcFinding]]:
    """Host'un RPC saldırı yüzeyini salt-okunur denetler (impacket, to_thread).

    ``(envanter, bulgular)`` döner.
    ``smb_port`` (445/139) ve/veya ``epm_open`` (135 açık) verilir — hangisi açıksa o yol denenir.
    Kimlik (``user``) boş bırakılabilir (anonim probe); verilirse kimlikli bind denenir.
    """
    info = await asyncio.to_thread(
        _probe_rpc, host, smb_port, epm_open, user, password, domain, timeout
    )
    return info, evaluate_rpc(info)
