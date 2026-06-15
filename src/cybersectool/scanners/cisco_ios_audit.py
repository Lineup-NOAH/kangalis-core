"""Cisco IOS SSH güvenlik denetimi (VII-2d) — SALT-OKUNUR.

Telnet KAPALI (iyi duruş) ama SSH ile yönetilen Cisco IOS / IOS-XE cihazlarının
sertleştirme duruşunu **SSH üzerinden** denetler. Telnet denetimi (IX-7c) yalnız
Telnet açıkken config okuyabildiğinden, doğru yapılandırılmış (SSH-only) cihazlar
denetlenemiyordu — bu modül o boşluğu kapatır.

``show version`` + ``show running-config`` salt-okunur komutlarını çalıştırır; hedefe
YAZMAZ. Cisco config sertleştirme değerlendiricileri ``telnet_audit`` modülündeki SAF,
zaten-test-edilmiş ``eval_cisco_*`` fonksiyonlarından yeniden kullanılır (tek kaynak).
Ek olarak yalnız-SSH bağlamında anlamlı yeni kontroller ekler: SSHv2 zorunluluğu,
zayıf/varsayılan SNMP community, AAA new-model yokluğu.

``eval_*``/yardımcı fonksiyonlar SAFtır (birim testi edilebilir); ``audit_cisco_ios``
ağ erişimi (asyncssh) yapar. Kimlik ZORUNLUDUR (config okumak için giriş gerekir).
"""

from __future__ import annotations

import asyncio
import contextlib
import re
from dataclasses import dataclass

import asyncssh
from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.core.compliance import derive_compliance, store_compliance
from cybersectool.core.findings import create_finding
from cybersectool.core.models import Severity
from cybersectool.scanners.telnet_audit import (
    TelnetFinding,
    eval_cisco_enable_secret,
    eval_cisco_http_server,
    eval_cisco_password_encryption,
    eval_cisco_vty_transport,
)

CISCO_SSH_PORT = 22


class CiscoIosAuditError(Exception):
    """Cisco IOS SSH denetimi sırasında kurtarılamayan hata (oturum hiç kurulamadı)."""


@dataclass
class CiscoIosInfo:
    """Cisco IOS SSH denetim envanteri (okunabildiği kadarıyla)."""

    host: str = ""
    reachable: bool = False  # SSH (22) bağlantısı kuruldu mu?
    logged_in: bool = False  # kimlik kabul edildi mi?
    hostname: str = ""  # running-config'den 'hostname'
    version: str = ""  # 'show version' ilk satırları
    running_config: str = ""  # 'show running-config' (kimlikliyse + yetkiliyse + TAM)
    config_truncated: bool = False  # config okundu ama eksik (paging/truncate) → değerlendirilmedi

    def summary(self) -> str:
        state = "erişildi" if self.reachable else "erişilemedi"
        host = f"{self.host} — SSH {state}"
        return f"{host} ({self.hostname})" if self.hostname else host


# Yeni (yalnız-SSH bağlamı) kontrol başlıkları.
SSH_VERSION_TITLE = "Cisco SSH sürümü"
SNMP_COMMUNITY_TITLE = "Cisco zayıf SNMP community"
AAA_TITLE = "Cisco AAA new-model"

# Bu denetimde çalışan tüm config kontrol başlıkları (4 devralınan + 3 yeni) — uyum eşlemesi.
CISCO_IOS_CONFIG_TITLES: tuple[str, ...] = (
    "Cisco parola şifreleme",
    "Cisco enable secret",
    "Cisco VTY transport",
    "Cisco HTTP sunucu",
    SSH_VERSION_TITLE,
    SNMP_COMMUNITY_TITLE,
    AAA_TITLE,
)

# Tahmin edilebilir / fabrika SNMP community dizeleri (RO ya da RW olabilir).
_WEAK_SNMP_COMMUNITIES = {"public", "private", "cisco", "community", "admin"}


def eval_cisco_ssh_version(config: str) -> TelnetFinding | None:
    """'ip ssh version 2' açıkça yoksa uyarı (düşük risk — operatör doğrulamalı).

    NOT: IOS-XE 17.x+'ta yalnız-SSHv2 VARSAYILAN olabildiğinden bu satır running-config'e
    yazılmayabilir (cihaz v2-only olsa bile). Bu yüzden kesin bir 'fail' değil; absence
    yalnız "doğrula" uyarısıdır (kesin duruş 'show ip ssh' ile görülür). Düşük şiddet,
    modern filolarda yanlış uyum-fail gürültüsünü önler.
    """
    if not re.search(r"(?m)^\s*ip ssh version 2\b", config):
        return TelnetFinding(
            SSH_VERSION_TITLE,
            Severity.low,
            "'ip ssh version 2' running-config'te açıkça görünmüyor — cihaz uyumluluk "
            "(compatibility) modunda güvensiz SSHv1'i KABUL EDEBİLİR. Not: IOS-XE 17.x+ "
            "sürümlerinde v2-only varsayılandır ve bu satır 'show running-config all' "
            "dışında gizlenebilir; kesin duruş için 'show ip ssh' çıktısını doğrulayın. "
            "Klasik IOS'ta 'ip ssh version 2' ile yalnız SSHv2'yi açıkça zorlayın.",
        )
    return None


def eval_cisco_snmp_community(config: str) -> TelnetFinding | None:
    """Varsayılan/zayıf SNMP community (public/private…) tanımlıysa (yüksek risk).

    'service password-encryption' açıkken community ŞİFRELİ görünür
    (``snmp-server community 7 <hash>``); şifreli (tip 5/7) biçimde düz-metin sözlük
    eşlemesi anlamsızdır (config'ten doğrulanamaz) → atlanır. İsteğe bağlı tip göstergesi
    (0/5/7) ayıklanıp gerçek community token'ı sözlükle kıyaslanır.
    """
    for match in re.finditer(r"(?mi)^\s*snmp-server community\s+(?:(\d+)\s+)?(\S+)", config):
        enc_type, token = match.group(1), match.group(2)
        if enc_type in {"5", "7"}:
            continue  # şifreli hash → düz-metin sözlük eşlemesi yapılamaz
        if token.lower() in _WEAK_SNMP_COMMUNITIES:
            return TelnetFinding(
                SNMP_COMMUNITY_TITLE,
                Severity.high,
                f"Varsayılan/zayıf SNMP community ('{token}') tanımlı — saldırgan cihaz "
                "envanterini/konfigürasyonunu okuyabilir; RW ise config'i değiştirebilir. "
                "Tahmin-edilemez bir community kullanın ve mümkünse SNMPv3 (kimlik + "
                "şifreleme) tercih edin.",
            )
    return None


def eval_cisco_aaa(config: str) -> TelnetFinding | None:
    """'aaa new-model' yoksa merkezi kimlik doğrulama/yetki/muhasebe yok (orta risk)."""
    if not re.search(r"(?m)^\s*aaa new-model\b", config):
        return TelnetFinding(
            AAA_TITLE,
            Severity.medium,
            "'aaa new-model' etkin değil — kimlik doğrulama/yetkilendirme/muhasebe merkezi "
            "değil (yalnız yerel parola). RADIUS/TACACS+ ile 'aaa new-model' yapılandırın; "
            "merkezi denetim izi ve hesap yönetimi sağlar.",
        )
    return None


# Cisco IOS config kontrolü → saf değerlendirme fonksiyonu (4 devralınan + 3 yeni).
_CONFIG_EVALS = (
    eval_cisco_password_encryption,
    eval_cisco_enable_secret,
    eval_cisco_vty_transport,
    eval_cisco_http_server,
    eval_cisco_ssh_version,
    eval_cisco_snmp_community,
    eval_cisco_aaa,
)


def evaluate_cisco_ios(info: CiscoIosInfo) -> list[TelnetFinding]:
    """Cisco IOS denetim envanterinden bulguları üretir (saf; ağ gerektirmez).

    Yalnız ``running_config`` okunabildiğinde değerlendirir — config yoksa (yetki yetmedi /
    komut reddedildi) yanlış "eksik direktif" bulgusu üretmez.
    """
    if not info.running_config:
        return []
    findings: list[TelnetFinding] = []
    for evaluate in _CONFIG_EVALS:
        verdict = evaluate(info.running_config)
        if verdict is not None:
            findings.append(verdict)
    return findings


def ran_titles_for(info: CiscoIosInfo) -> list[str]:
    """Bu denetimde GERÇEKTEN çalışan kontrol başlıkları (uyum eşlemesi için)."""
    return list(CISCO_IOS_CONFIG_TITLES) if info.running_config else []


# --- Saf yardımcılar (ağsız, test edilebilir) ---


def _first_lines(text: str, count: int = 3) -> str:
    """Çıktının ilk anlamlı satırlarını tek satıra birleştirir (envanter özeti)."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return " | ".join(lines[:count])[:200]


def _hostname_from_config(config: str) -> str:
    """running-config'deki 'hostname X' satırından cihaz adını çıkarır."""
    match = re.search(r"(?m)^\s*hostname\s+(\S+)", config)
    return match.group(1) if match else ""


def _looks_like_config(text: str) -> bool:
    """Çıktı gerçekten bir running-config mi? (yetki yetmezse hata/banner gelir, config değil).

    Komut reddedilince ('% Invalid input' / '% Authorization failed') bunu config sanıp
    sertleştirme değerlendirmesi yapmamak için ayırt-edici bir işaret aranır.
    """
    low = text.lower()
    markers = (
        "hostname ",
        "interface ",
        "line vty",
        "building configuration",
        "current configuration",
    )
    return any(marker in low for marker in markers)


def _config_is_complete(text: str) -> bool:
    """running-config TAM okundu mu? Cisco running-config satır-başı 'end' ile biter.

    Paging ('--More--') ya da timeout config'i KESERSE 'end' bulunmaz → eksik sayılır.
    Eksik config'i değerlendirmek, sayfa sınırından sonraki direktifleri (ör. alt
    satırlardaki snmp-server community / transport input) görmediğinden YANLIŞ 'geçti'
    uyum sonucu üretir; bu yüzden tam olmayan config değerlendirilmez (bkz. audit).
    """
    return bool(re.search(r"(?m)^\s*end\s*$", text))


# --- Ağ erişimi (asyncssh) ---


async def _fetch_running_config(conn: asyncssh.SSHClientConnection, timeout: float) -> str:
    """'show running-config'i PAGING KAPALI okur (tam config döndürmeye çalışır).

    Cisco IOS varsayılan olarak çıktıyı sayfalar ('--More--'); ayrı ``conn.run`` kanalları
    terminal-length state paylaşmadığından önce interaktif bir oturumda 'terminal length 0'
    + 'show running-config' AYNI kanalda gönderilir. Tam config alınamazsa tek-exec'e düşülür
    (completeness guard truncate'i yine yakalar). Hiçbir şey YAZILMAZ (yalnız 'show').
    """

    def _norm(raw: object) -> str:
        return str(raw or "").replace("\r\n", "\n").replace("\r", "\n")

    # 1) İnteraktif oturum: paging kapalı → tam config.
    with contextlib.suppress(asyncssh.Error, OSError, TimeoutError):
        async with conn.create_process(term_type="vt100") as proc:
            proc.stdin.write("terminal length 0\nshow running-config\nexit\n")
            text = _norm(await asyncio.wait_for(proc.stdout.read(), timeout))
        if _config_is_complete(text):
            return text
    # 2) Yedek: tek exec (paging kapalı olmayabilir → completeness guard truncate'i yakalar).
    with contextlib.suppress(asyncssh.Error, OSError):
        res = await conn.run("show running-config", check=False)
        return _norm(res.stdout)
    return ""


async def audit_cisco_ios(
    host: str,
    port: int = CISCO_SSH_PORT,
    *,
    user: str,
    password: str,
    timeout: float = 12.0,
) -> tuple[CiscoIosInfo, list[TelnetFinding]]:
    """Cisco IOS cihazına SSH ile salt-okunur bağlanıp sertleştirme duruşunu denetler.

    ``show version`` + ``show running-config`` çalıştırır (YAZMAZ). Kimlik ZORUNLUDUR.
    Bağlanılamaz / kimlik reddedilirse ``CiscoIosAuditError`` (çağıran 'başarısız' işaretler).
    Komut bazında hata (yetki yetmedi) yutulur — envanter eksik kalır ama denetim çökmez.
    ``(envanter, bulgular)`` döner.
    """
    info = CiscoIosInfo(host=host)
    try:
        async with asyncssh.connect(
            host,
            port=port,
            username=user,
            password=password,
            known_hosts=None,
            connect_timeout=timeout,
        ) as conn:
            info.reachable = True
            info.logged_in = True  # bağlantı + kimlik kabul edildi
            with contextlib.suppress(asyncssh.Error, OSError):
                ver = await conn.run("show version", check=False)
                info.version = _first_lines(str(ver.stdout or ""))
            config = await _fetch_running_config(conn, timeout)
            if _looks_like_config(config):
                if _config_is_complete(config):
                    info.running_config = config  # TAM → değerlendirilir
                    info.hostname = _hostname_from_config(config)
                else:
                    # Okundu ama eksik (paging/truncate): değerlendirme ATLA → sahte uyum-geçti yok.
                    info.config_truncated = True
                    info.hostname = _hostname_from_config(config)
    except asyncssh.PermissionDenied as exc:
        raise CiscoIosAuditError(f"SSH kimlik doğrulama başarısız: {exc}") from exc
    except (OSError, asyncssh.Error, TimeoutError) as exc:
        raise CiscoIosAuditError(f"Cisco IOS SSH bağlantısı kurulamadı: {exc}") from exc
    return info, evaluate_cisco_ios(info)


async def store_cisco_ios_audit(
    session: AsyncSession,
    scan_id: int,
    info: CiscoIosInfo,
    findings: list[TelnetFinding],
) -> None:
    """Cisco IOS envanteri (info) + denetim bulgularını + CIS uyumunu Finding olarak kaydeder."""
    if info.running_config:
        config_state = f"{len(info.running_config)} bayt"
    elif info.config_truncated:
        config_state = "okundu ama EKSİK (paging/truncate) — değerlendirme atlandı"
    else:
        config_state = "okunamadı"
    await create_finding(
        session,
        scan_id,
        f"Cisco IOS SSH envanteri: {info.summary()[:140]}",
        severity=Severity.info,
        description=(
            f"SSH={'erişildi' if info.reachable else 'erişilemedi'} · "
            f"giriş={'başarılı' if info.logged_in else 'yok'} · "
            f"sürüm: {info.version or '—'} · running-config: {config_state}"
        ),
    )
    for finding in findings:
        await create_finding(
            session, scan_id, finding.title, severity=finding.severity, description=finding.detail
        )
    # Uyum (CIS Cisco): bu denetimde gerçekten çalışan kontrolleri geçti/kaldı eşle.
    failed = {f.title: (f.severity, f.detail) for f in findings}
    await store_compliance(session, scan_id, derive_compliance(ran_titles_for(info), failed))
