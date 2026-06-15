"""Telnet / Cisco IOS CLI güvenlik denetimi (IX-7c) — SALT-OKUNUR.

Bir ağ cihazının (switch/router) Telnet yönetim düzlemini denetler: Telnet'in açık
(şifresiz yönetim) olması, yetkisiz-erişim uyarı banner'ının yokluğu ve — kimlik
verilirse — ``show running-config`` çıktısından Cisco sertleştirme kontrolleri
(service password-encryption, enable secret, VTY transport, HTTP sunucu).

Hedefe YAZMAZ — yalnız bağlanır, banner okur ve (kimlikliyse) salt-okunur ``show``
komutları çalıştırır. ``eval_*`` fonksiyonları SAFtır (birim testi edilebilir);
``audit_telnet`` ağ erişimi yapar (gerçek/simüle Telnet cihazına karşı doğrulanır).

Telnet etkileşimi ``asyncio`` akışları + minimal IAC (telnet seçenek) işleme ile yapılır;
``telnetlib`` KULLANILMAZ (Python 3.13'te kaldırıldı). Kimlik OPSİYONELDİR: kimliksiz de
Telnet açıklığı + banner tespit edilir.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.core.compliance import derive_compliance, store_compliance
from cybersectool.core.findings import create_finding
from cybersectool.core.models import Severity

TELNET_PORT = 23

# Telnet IAC (Interpret As Command) sabitleri (RFC 854).
_IAC = 255
_DONT = 254
_DO = 253
_WONT = 252
_WILL = 251
_SB = 250
_SE = 240


class TelnetAuditError(Exception):
    """Telnet denetimi sırasında kurtarılamayan hata (hedefe hiç erişilemedi)."""


@dataclass
class TelnetFinding:
    title: str
    severity: Severity
    detail: str


@dataclass
class TelnetInfo:
    """Telnet denetim sonucu envanteri (okunabildiği/denenebildiği kadarıyla)."""

    host: str = ""
    telnet_open: bool = False  # 23/telnet TCP bağlantısı kuruldu mu?
    banner: str = ""  # giriş öncesi banner (temizlenmiş)
    logged_in: bool = False  # verilen kimlikle CLI'a girildi mi?
    hostname: str = ""  # prompt'tan çıkarılan cihaz adı
    running_config: str = ""  # 'show running-config' çıktısı (kimlikliyse)

    def summary(self) -> str:
        """Kısa tek satır özet."""
        state = "açık" if self.telnet_open else "kapalı"
        host = f"{self.host} — Telnet {state}"
        return f"{host} ({self.hostname})" if self.hostname else host


# Çekirdek kontrol başlıkları (Telnet açıklığı her zaman; banner yalnız Telnet açıksa).
TELNET_OPEN_TITLE = "Telnet şifresiz yönetim"
TELNET_BANNER_TITLE = "Telnet uyarı banner"
# Cisco running-config kontrolleri (yalnız kimlikli config okunduğunda çalışır).
CISCO_CONFIG_TITLES: tuple[str, ...] = (
    "Cisco parola şifreleme",
    "Cisco enable secret",
    "Cisco VTY transport",
    "Cisco HTTP sunucu",
)


def eval_telnet_open(telnet_open: bool) -> TelnetFinding | None:
    """Telnet açıksa yönetim trafiği (parola dahil) düz metin gider (yüksek risk)."""
    if telnet_open:
        return TelnetFinding(
            TELNET_OPEN_TITLE,
            Severity.high,
            "Cihaz Telnet (TCP/23) ile yönetilebiliyor — kullanıcı adı, parola ve tüm "
            "oturum ağ üzerinde DÜZ METİN gider; pasif dinleyen saldırgan kimlik bilgisini "
            "ele geçirir. Telnet'i kapatın ve yalnız SSH kullanın.",
        )
    return None


def eval_telnet_warning_banner(banner: str) -> TelnetFinding | None:
    """Yetkisiz-erişim uyarı banner'ı yoksa yasal/uyum eksikliği (düşük risk)."""
    low = banner.lower()
    keywords = ("authorized", "unauthorized", "warning", "yetkisiz", "izinsiz", "yasak")
    if not any(k in low for k in keywords):
        return TelnetFinding(
            TELNET_BANNER_TITLE,
            Severity.low,
            "Giriş öncesi yetkisiz-erişim uyarı banner'ı (login/MOTD) görünmüyor — birçok "
            "uyum çerçevesi yasal uyarı banner'ı ister. 'banner login' ile yetkisiz erişimin "
            "yasak olduğunu belirten bir uyarı tanımlayın.",
        )
    return None


def eval_cisco_password_encryption(config: str) -> TelnetFinding | None:
    """'service password-encryption' yoksa parolalar config'de düz metin (orta risk)."""
    if not re.search(r"(?m)^\s*service password-encryption\b", config):
        return TelnetFinding(
            "Cisco parola şifreleme",
            Severity.medium,
            "'service password-encryption' etkin değil — config içindeki parolalar düz metin "
            "saklanır (yedek/ekran görüntüsü sızıntısı riski). 'service password-encryption' "
            "komutunu etkinleştirin.",
        )
    return None


def eval_cisco_enable_secret(config: str) -> TelnetFinding | None:
    """'enable password' (zayıf/geri çevrilebilir) varken 'enable secret' yoksa (yüksek risk)."""
    has_secret = bool(re.search(r"(?m)^\s*enable secret\b", config))
    has_plain = bool(re.search(r"(?m)^\s*enable password\b", config))
    if has_plain and not has_secret:
        return TelnetFinding(
            "Cisco enable secret",
            Severity.high,
            "Ayrıcalıklı mod parolası 'enable password' ile tanımlı (zayıf, geri çevrilebilir "
            "Tip 7 / düz metin) ve 'enable secret' yok. 'enable secret' (Tip 8/9 hash) "
            "kullanın ve 'enable password' satırını kaldırın.",
        )
    return None


def eval_cisco_vty_transport(config: str) -> TelnetFinding | None:
    """VTY hatlarında 'transport input telnet/all' varsa uzaktan şifresiz erişim (orta risk)."""
    if re.search(r"(?m)^\s*transport input (telnet|all)\b", config):
        return TelnetFinding(
            "Cisco VTY transport",
            Severity.medium,
            "VTY hatlarında 'transport input telnet' (veya 'all') tanımlı — uzaktan şifresiz "
            "yönetime izin verir. VTY satırlarında 'transport input ssh' kullanın.",
        )
    return None


def eval_cisco_http_server(config: str) -> TelnetFinding | None:
    """'ip http server' (şifresiz HTTP yönetimi) açıksa (orta risk)."""
    has_http = bool(re.search(r"(?m)^\s*ip http server\b", config))
    if has_http:
        return TelnetFinding(
            "Cisco HTTP sunucu",
            Severity.medium,
            "'ip http server' etkin — cihaz yönetimi şifresiz HTTP üzerinden açık. 'no ip http "
            "server' ile kapatın; gerekiyorsa yalnız 'ip http secure-server' (HTTPS) kullanın.",
        )
    return None


# Cisco config kontrolü başlığı → saf değerlendirme fonksiyonu.
_CISCO_EVALS = (
    eval_cisco_password_encryption,
    eval_cisco_enable_secret,
    eval_cisco_vty_transport,
    eval_cisco_http_server,
)


def evaluate_telnet(info: TelnetInfo) -> list[TelnetFinding]:
    """Telnet denetim envanterinden bulguları üretir (saf; ağ gerektirmez)."""
    findings: list[TelnetFinding] = []
    verdict = eval_telnet_open(info.telnet_open)
    if verdict is not None:
        findings.append(verdict)
    if info.telnet_open:
        banner_verdict = eval_telnet_warning_banner(info.banner)
        if banner_verdict is not None:
            findings.append(banner_verdict)
    if info.running_config:
        for evaluate in _CISCO_EVALS:
            config_verdict = evaluate(info.running_config)
            if config_verdict is not None:
                findings.append(config_verdict)
    return findings


def ran_titles_for(info: TelnetInfo) -> list[str]:
    """Bu denetimde GERÇEKTEN çalışan kontrol başlıkları (uyum eşlemesi için)."""
    titles = [TELNET_OPEN_TITLE]
    if info.telnet_open:
        titles.append(TELNET_BANNER_TITLE)
    if info.running_config:
        titles.extend(CISCO_CONFIG_TITLES)
    return titles


# --- Ağ erişimi (asyncio telnet — minimal IAC) ---


def _process_iac(data: bytes) -> tuple[bytes, bytes, bytes]:
    """Ham telnet baytlarından IAC seçeneklerini ayıklar; (temiz metin, yanıt, kalan ham) döner.

    Tüm seçenekler reddedilir (DO→WONT, WILL→DONT) → sunucu veri akışına geçer. Bir IAC dizisi
    okuma sınırında YARIM kalırsa atılmaz; 'kalan ham' olarak döner ve çağıran bir sonraki
    chunk'ın başına ekler (chunk'lar arası senkron korunur).
    """
    out = bytearray()
    resp = bytearray()
    i, n = 0, len(data)
    while i < n:
        byte = data[i]
        if byte != _IAC:
            out.append(byte)
            i += 1
            continue
        if i + 1 >= n:
            return bytes(out), bytes(resp), data[i:]  # yarım IAC → beklet
        cmd = data[i + 1]
        if cmd in (_DO, _DONT, _WILL, _WONT):
            if i + 2 >= n:
                return bytes(out), bytes(resp), data[i:]  # yarım opsiyon → beklet
            opt = data[i + 2]
            if cmd == _DO:
                resp += bytes([_IAC, _WONT, opt])
            elif cmd == _WILL:
                resp += bytes([_IAC, _DONT, opt])
            i += 3
        elif cmd == _SB:
            j = i + 2
            while j + 1 < n and not (data[j] == _IAC and data[j + 1] == _SE):
                j += 1
            if j + 1 >= n:
                return bytes(out), bytes(resp), data[i:]  # IAC SE gelmedi → beklet
            i = j + 2
        elif cmd == _IAC:
            out.append(_IAC)
            i += 2
        else:
            i += 2
    return bytes(out), bytes(resp), b""


async def _read_until(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    prompts: tuple[str, ...],
    *,
    overall: float,
    idle: float = 1.2,
) -> str:
    """Bir prompt görülene / veri akışı durana (idle) / toplam süre dolana kadar okur.

    IAC seçenekleri işlenir ve gerekli yanıtlar geri yazılır. Dönen metin temizlenmemiştir.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + overall
    text = ""
    pending = b""  # sınırda yarım kalan IAC dizisi → sonraki chunk'ın başına eklenir
    while loop.time() < deadline:
        try:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=idle)
        except TimeoutError:
            break  # veri akışı durdu → bitti varsay
        if not chunk:
            break  # EOF
        clean, resp, pending = _process_iac(pending + chunk)
        if resp:
            writer.write(resp)
            with contextlib.suppress(Exception):
                await writer.drain()
        text += clean.decode("utf-8", errors="replace")
        if prompts and any(p in text.lower() for p in prompts):
            break
    return text


def _clean_text(raw: str) -> str:
    """Telnet çıktısından ANSI escape + yazdırılamayan baytları (DEL/C1 dahil) ayıklar."""
    raw = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", raw)  # ANSI/VT100 CSI dizileri (ör. [0m, [2J)
    # Yazdırılabilir aralik 0x20–0x7E + \n/\t; DEL (0x7F), C1 (0x80–0x9F) ve lone ESC elenir.
    return "".join(ch for ch in raw if ch in ("\n", "\t") or " " <= ch < "\x7f").strip()


def _prompt_hostname(prompt: str) -> str:
    """CLI prompt'undan cihaz adını çıkarır (ör. 'Router#' → 'Router')."""
    match = re.search(r"([\w.-]+)\s*[>#]\s*$", prompt.strip())
    return match.group(1) if match else ""


async def _do_login(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    info: TelnetInfo,
    user: str,
    password: str,
    timeout: float,
) -> None:
    """Telnet ile kimlikli giriş + 'show running-config' (salt-okunur). Hata yutulur."""
    writer.write((user + "\r\n").encode())
    await writer.drain()
    await _read_until(reader, writer, ("password:",), overall=timeout)
    writer.write((password + "\r\n").encode())
    await writer.drain()
    prompt = await _read_until(reader, writer, (">", "#"), overall=timeout)
    # Gevşek '#'/'>' substring araması banner/MOTD (ör. '####') ile yanlış-pozitif verir;
    # satır-sonu çıpalı CLI prompt'u (hostname>/hostname#) ara. Başarısız giriş işaretlerini reddet.
    fail_markers = ("username:", "login:", "authentication failed", "% login", "access denied")
    if any(m in prompt.lower() for m in fail_markers):
        return  # giriş başarısız (yeniden prompt / hata mesajı)
    hostname = _prompt_hostname(prompt)
    if not hostname:
        return  # giriş başarısız (gerçek CLI prompt'u tanınmadı)
    info.logged_in = True
    info.hostname = hostname
    writer.write(b"terminal length 0\r\n")
    await writer.drain()
    await _read_until(reader, writer, ("#", ">"), overall=timeout)
    writer.write(b"show running-config\r\n")
    await writer.drain()
    config = await _read_until(reader, writer, (), overall=max(timeout, 10.0), idle=1.5)
    info.running_config = _clean_text(config)


async def audit_telnet(
    host: str,
    port: int = TELNET_PORT,
    *,
    user: str = "",
    password: str = "",
    timeout: float = 8.0,
) -> tuple[TelnetInfo, list[TelnetFinding]]:
    """Telnet/Cisco cihazına salt-okunur bağlanıp güvenlik duruşunu denetler (asyncio telnet).

    Telnet portu kapalıysa (bağlantı reddi) ``telnet_open=False`` ile tamamlanır (iyi duruş —
    bulgu yok). Kimlik (``user``) boş bırakılabilir — açıklık + banner yine tespit edilir.
    Erişilemezse (timeout) ``TelnetAuditError``. ``(envanter, bulgular)`` döner.
    """
    info = TelnetInfo(host=host)
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except ConnectionRefusedError:
        info.telnet_open = False
        return info, evaluate_telnet(info)
    except (TimeoutError, OSError) as exc:
        raise TelnetAuditError(f"Telnet bağlantısı kurulamadı: {exc}") from exc
    info.telnet_open = True
    try:
        banner = await _read_until(
            reader, writer, ("username:", "login:", "password:"), overall=5.0
        )
        info.banner = _clean_text(banner)
        if user:
            await _do_login(reader, writer, info, user, password, timeout)
    finally:
        with contextlib.suppress(Exception):
            writer.close()
            await (
                writer.wait_closed()
            )  # transport tam kapanana dek bekle (soket/fd sızıntısı önler)
    return info, evaluate_telnet(info)


async def store_telnet_audit(
    session: AsyncSession,
    scan_id: int,
    info: TelnetInfo,
    findings: list[TelnetFinding],
) -> None:
    """Telnet envanteri (info) + denetim bulgularını + CIS uyumunu Finding olarak kaydeder."""
    banner = info.banner.splitlines()[0][:80] if info.banner else "—"
    config_state = f"{len(info.running_config)} bayt" if info.running_config else "okunmadı"
    await create_finding(
        session,
        scan_id,
        f"Telnet envanteri: {info.summary()[:140]}",
        severity=Severity.info,
        description=(
            f"Telnet={'açık' if info.telnet_open else 'kapalı'} · "
            f"giriş={'başarılı' if info.logged_in else 'yok'} · banner: {banner} · "
            f"running-config: {config_state}"
        ),
    )
    for finding in findings:
        await create_finding(
            session, scan_id, finding.title, severity=finding.severity, description=finding.detail
        )
    # Uyum (CIS Cisco): bu denetimde gerçekten çalışan kontrolleri geçti/kaldı eşle.
    failed = {f.title: (f.severity, f.detail) for f in findings}
    await store_compliance(session, scan_id, derive_compliance(ran_titles_for(info), failed))
