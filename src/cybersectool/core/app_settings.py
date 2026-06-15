"""Uygulama ayarları (DB) — tek satırlık ``app_settings`` (id=1).

Admin ``/settings`` sayfasından yönetilen güvenlik/operasyon ayarları. Ortam
değişkenleri (config.py) yalnızca varsayılan/fallback'tir; DB'deki değer önceliklidir.

``get_settings`` her zaman bir satır döndürür (yoksa varsayılanlarla oluşturur),
böylece çağıran taraf ``None`` kontrolü yapmaz. SMTP parolası Fernet ile şifreli
saklanır; boş gönderilirse mevcut parola korunur (LdapConfig deseni).
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from zoneinfo import ZoneInfo, available_timezones

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.core.crypto import decrypt_secret, encrypt_secret
from cybersectool.core.models import AppSettings
from cybersectool.core.scan_policy import normalize_fanout_workers, normalize_scan_speed

SYSLOG_PROTOCOLS: tuple[str, ...] = ("udp", "tcp")
SYSLOG_FORMATS: tuple[str, ...] = ("rfc5424", "rfc3164", "cef")

# --- Saat dilimi (IX-1) ---
DEFAULT_TIMEZONE = "Europe/Istanbul"

# Ayarlar açılır listesinde gösterilen yaygın iş saat dilimleri (hepsi IANA geçerli).
COMMON_TIMEZONES: tuple[str, ...] = (
    "UTC",
    "Europe/Istanbul",
    "Europe/London",
    "Europe/Berlin",
    "Europe/Paris",
    "Europe/Amsterdam",
    "Europe/Moscow",
    "America/New_York",
    "America/Chicago",
    "America/Denver",
    "America/Los_Angeles",
    "America/Sao_Paulo",
    "Asia/Dubai",
    "Asia/Tehran",
    "Asia/Karachi",
    "Asia/Kolkata",
    "Asia/Shanghai",
    "Asia/Tokyo",
    "Asia/Singapore",
    "Australia/Sydney",
)

# Uygulama geneli saat dilimi cache'i (web süreci içi). DB'den ``get_settings`` ve
# ``save_timezone_settings`` ile tazelenir; şablon filtresi (localdt) bunu okur.
_tz_cache: str = DEFAULT_TIMEZONE


def get_app_timezone() -> str:
    """Geçerli uygulama saat dilimini (cache'ten) döndürür."""
    return _tz_cache


def set_app_timezone_cache(tz: str) -> None:
    """Saat dilimi cache'ini günceller (get/save tarafından çağrılır)."""
    global _tz_cache
    _tz_cache = tz


# AI marka modu cache'i (web süreci içi). AI eklentisi (``ai_enabled``) etkinse arayüz markası
# "Kangalis" yerine "Kangalis AI" olur. ``get_settings`` + ``save_ai_settings`` ile tazelenir;
# sync context processor (_i18n_context) DB okuyamaz → bunu okur (timezone cache deseniyle aynı).
_ai_brand_cache: bool = False


def ai_brand_enabled() -> bool:
    """AI eklentisi etkin mi (arayüz markası 'Kangalis AI' için) — cache'ten döndürür."""
    return _ai_brand_cache


def set_ai_brand_cache(enabled: bool) -> None:
    """AI marka cache'ini günceller (get_settings/save_ai_settings tarafından çağrılır)."""
    global _ai_brand_cache
    _ai_brand_cache = bool(enabled)


def valid_timezone(tz: str) -> str:
    """Geçerli bir IANA saat dilimi ise döndürür, değilse varsayılana düşer."""
    candidate = (tz or "").strip()
    return candidate if candidate in available_timezones() else DEFAULT_TIMEZONE


def _zone(name: str) -> ZoneInfo:
    """Saat dilimi adından ZoneInfo üretir; geçersizse UTC'ye düşer."""
    try:
        return ZoneInfo(name)
    except Exception:
        # Geçersiz/eksik tz veritabanında UTC güvenli varsayılan.
        return ZoneInfo("UTC")


def to_local(dt: datetime) -> datetime:
    """UTC/naive bir datetime'ı uygulama saat dilimine çevirir."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(_zone(get_app_timezone()))


def format_local(dt: datetime | None, fmt: str = "%Y-%m-%d %H:%M") -> str:
    """datetime'ı yerel saat dilimine çevirip biçimler; None ise tire döndürür."""
    if dt is None:
        return "—"
    return to_local(dt).strftime(fmt)


def clean_dns_servers(raw: str) -> str:
    """DNS sunucu listesini temizler — yalnızca GEÇERLİ IP'leri tutar (komut enjeksiyonu koruması).

    nmap ``--dns-servers`` argümanına gideceği için sadece doğrulanmış IP adresleri
    (virgülle) kalır; geçersiz/zararlı token'lar atılır. En fazla 3 sunucu.
    """
    valid: list[str] = []
    for token in (raw or "").replace(";", ",").split(","):
        candidate = token.strip()
        if not candidate:
            continue
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if candidate not in valid:
            valid.append(candidate)
    return ",".join(valid[:3])


def parse_asset_scope_cidrs(raw: str) -> list[str]:
    """Metin alanını (satır/virgül ayrık) doğrulanmış CIDR listesine çevirir (F1).

    Tek IP de kabul edilir (``1.2.3.4`` → ``1.2.3.4/32``); geçersiz token'lar atılır;
    sıra korunur, tekrarlar elenir. Boş sonuç = kapsam zorlanmaz (tüm IP'ler asset olabilir).
    """
    out: list[str] = []
    seen: set[str] = set()
    for token in (raw or "").replace(",", "\n").splitlines():
        candidate = token.strip()
        if not candidate:
            continue
        try:
            net = ipaddress.ip_network(candidate, strict=False)
        except ValueError:
            continue
        text = str(net)
        if text not in seen:
            seen.add(text)
            out.append(text)
    return out


async def save_asset_scope_settings(session: AsyncSession, *, raw_cidrs: str) -> AppSettings:
    """Varlık kapsamı (asset scope) CIDR'lerini doğrulayıp kaydeder (F1)."""
    row = await get_settings(session)
    row.asset_scope_cidrs = parse_asset_scope_cidrs(raw_cidrs)
    await session.commit()
    await session.refresh(row)
    return row


# NVD senkron penceresi güvenli sınırları (gün): en az 1 gün (operatör çok kısa bir günlük
# tazeleme penceresi seçebilsin — örn. 3 gün), en çok ~2 yıl. Geçmiş yükleme ayrı backfill'dir.
NVD_SYNC_DAYS_MIN = 1
NVD_SYNC_DAYS_MAX = 730


async def save_nvd_settings(
    session: AsyncSession, *, sync_days: int, api_key: str | None = None
) -> AppSettings:
    """NVD senkron kapsamını (gün) + opsiyonel API anahtarını kaydeder (CVE-COVERAGE FE).

    ``sync_days`` güvenli aralığa sıkıştırılır. ``api_key`` boş/None ise mevcut şifreli
    anahtar KORUNUR (formu boş bırakarak günceller); doluysa Fernet ile şifrelenir.
    """
    row = await get_settings(session)
    row.nvd_sync_days = _clamp(sync_days, NVD_SYNC_DAYS_MIN, NVD_SYNC_DAYS_MAX)
    if api_key:
        row.nvd_api_key_encrypted = encrypt_secret(api_key.strip())
    await session.commit()
    await session.refresh(row)
    return row


def get_nvd_api_key(row: AppSettings) -> str:
    """Şifreli NVD API anahtarını çözer (yoksa boş dize)."""
    if not row.nvd_api_key_encrypted:
        return ""
    return decrypt_secret(row.nvd_api_key_encrypted)


async def record_cve_sync(session: AsyncSession, when: datetime) -> None:
    """Başarılı CVE/CPE senkronu (cpe_sync/backfill) → son-senkron zamanını kaydeder.

    Exploit deposu tazeliğinden (``exploit_last_sync``) AYRIDIR — CVE/CPE bilgi bankası
    kendi tazeliğini taşır (Zafiyet DB sayfası + Ayarlar paneli bunu gösterir).
    """
    row = await get_settings(session)
    row.cve_last_sync = when
    await session.commit()


def _clamp(value: int, low: int, high: int) -> int:
    """Bir tamsayıyı [low, high] aralığına sıkıştırır (güvenli sınırlar)."""
    return max(low, min(high, value))


async def get_settings(session: AsyncSession) -> AppSettings:
    """Ayar satırını döndürür; yoksa varsayılanlarla oluşturur (asla None)."""
    result = await session.execute(select(AppSettings).where(AppSettings.id == 1))
    row = result.scalar_one_or_none()
    if row is None:
        row = AppSettings(id=1)
        session.add(row)
        await session.commit()
        await session.refresh(row)
    set_app_timezone_cache(row.timezone)  # şablon filtresi için cache'i tazele
    set_ai_brand_cache(
        row.ai_enabled
    )  # AI marka modu cache'i (Kangalis AI) — context processor okur
    return row


async def save_timezone_settings(session: AsyncSession, *, timezone: str) -> AppSettings:
    """Uygulama geneli saat dilimini kaydeder (IANA doğrulamalı) + cache'i günceller."""
    row = await get_settings(session)
    row.timezone = valid_timezone(timezone)
    await session.commit()
    await session.refresh(row)
    set_app_timezone_cache(row.timezone)
    return row


async def save_ldap_sync_settings(
    session: AsyncSession, *, enabled: bool, period: str, hour: int
) -> AppSettings:
    """LDAP periyodik senkron zamanlamasını kaydeder (X-6; period/saat doğrulamalı)."""
    row = await get_settings(session)
    row.ldap_sync_enabled = enabled
    row.ldap_sync_period = period if period in ("hourly", "daily", "weekly") else "daily"
    row.ldap_sync_hour = _clamp(hour, 0, 23)
    await session.commit()
    await session.refresh(row)
    return row


async def save_ratelimit_settings(
    session: AsyncSession,
    *,
    enabled: bool,
    max_attempts: int,
    window_sec: int,
    lockout_sec: int,
) -> AppSettings:
    """Giriş kaba-kuvvet koruması ayarlarını kaydeder (sınırlar güvenli aralığa çekilir)."""
    row = await get_settings(session)
    row.ratelimit_enabled = enabled
    row.ratelimit_max_attempts = _clamp(max_attempts, 1, 100)
    row.ratelimit_window_sec = _clamp(window_sec, 10, 86_400)
    row.ratelimit_lockout_sec = _clamp(lockout_sec, 10, 86_400)
    await session.commit()
    await session.refresh(row)
    return row


async def save_smtp_settings(
    session: AsyncSession,
    *,
    enabled: bool,
    host: str,
    port: int,
    username: str,
    sender: str,
    use_tls: bool,
    alert_to: str,
    password: str | None = None,
) -> AppSettings:
    """SMTP ve e-posta uyarı ayarlarını kaydeder.

    ``password`` boş/None ise mevcut şifreli parola korunur (formu parola alanını
    boş bırakarak güncellemek için).
    """
    row = await get_settings(session)
    row.smtp_enabled = enabled
    row.smtp_host = host.strip()
    row.smtp_port = _clamp(port, 1, 65_535)
    row.smtp_username = username.strip()
    row.smtp_from = sender.strip()
    row.smtp_use_tls = use_tls
    row.alert_email_to = alert_to.strip()
    if password:
        row.smtp_password_encrypted = encrypt_secret(password)
    await session.commit()
    await session.refresh(row)
    return row


async def save_syslog_settings(
    session: AsyncSession,
    *,
    enabled: bool,
    host: str,
    port: int,
    protocol: str,
    fmt: str,
) -> AppSettings:
    """Syslog/SIEM forward ayarlarını kaydeder (protokol/format beyaz listeli)."""
    row = await get_settings(session)
    row.syslog_enabled = enabled
    row.syslog_host = host.strip()
    row.syslog_port = _clamp(port, 1, 65_535)
    row.syslog_protocol = protocol if protocol in SYSLOG_PROTOCOLS else "udp"
    row.syslog_format = fmt if fmt in SYSLOG_FORMATS else "rfc5424"
    await session.commit()
    await session.refresh(row)
    return row


async def save_hardening_settings(
    session: AsyncSession,
    *,
    session_timeout_min: int,
    password_min_length: int,
    password_require_complexity: bool,
    ldaps_verify_cert: bool,
    ldaps_ca_cert: str | None = None,
    mfa_required: bool | None = None,
) -> AppSettings:
    """Oturum/parola/LDAPS sertleştirme ayarlarını kaydeder.

    ``mfa_required`` yalnızca açıkça verilirse güncellenir (None ise korunur) —
    org MFA anahtarı Kullanıcılar bölümünden yönetildiği için burada ezilmez.
    """
    row = await get_settings(session)
    row.session_timeout_min = _clamp(session_timeout_min, 0, 10_080)  # 0..1 hafta (dk)
    row.password_min_length = _clamp(password_min_length, 4, 128)
    row.password_require_complexity = password_require_complexity
    row.ldaps_verify_cert = ldaps_verify_cert
    if ldaps_ca_cert is not None:
        row.ldaps_ca_cert = ldaps_ca_cert.strip() or None
    if mfa_required is not None:
        row.mfa_required = mfa_required
    await session.commit()
    await session.refresh(row)
    return row


async def save_network_settings(
    session: AsyncSession,
    *,
    dns_servers: str,
    reverse_dns_enabled: bool,
    scan_speed: str | None = None,
) -> AppSettings:
    """Ağ/DNS + tarama hızı ayarlarını kaydeder. DNS sunucuları enjeksiyona karşı temizlenir.

    DNS yalnız geçerli IP'leri tutar. ``scan_speed`` (normal/fast/insane) nmap paralellik
    bayraklarını belirler; geçersiz/None verilirse güvenli ``fast``a normalize edilir
    (bilinmeyen değer tarama komutuna sızmaz).
    """
    row = await get_settings(session)
    row.dns_servers = clean_dns_servers(dns_servers)
    row.reverse_dns_enabled = reverse_dns_enabled
    if scan_speed is not None:
        row.scan_speed = normalize_scan_speed(scan_speed)
    await session.commit()
    await session.refresh(row)
    return row


async def save_scan_settings(
    session: AsyncSession,
    *,
    scan_speed: str,
    scan_fanout: bool,
    fanout_workers: int | None,
) -> AppSettings:
    """Tarama hızı + worker dağıtımı (fan-out) ayarlarını kaydeder (DNS'ten AYRI bölüm).

    ``scan_speed`` geçersizse güvenli ``fast``a normalize edilir. ``scan_fanout`` tek taramanın
    bloklara bölünüp worker'lara dağıtılıp dağıtılmayacağını; ``fanout_workers`` (1-32'ye kısılır)
    tek-host büyük-port taramasının kaç port-bloğuna bölüneceğini belirler. Tarama HIZINDAN
    bağımsızdır — her child yine yapılandırılan hız profilini kullanır.
    """
    row = await get_settings(session)
    row.scan_speed = normalize_scan_speed(scan_speed)
    row.scan_fanout = scan_fanout
    row.fanout_workers = normalize_fanout_workers(fanout_workers)
    await session.commit()
    await session.refresh(row)
    return row


def normalize_ai_timeout(value: int | None) -> int:
    """AI üst zaman aşımını güvenli aralığa kısar (5-600 sn). CPU çıkarımı yavaş → cömert.

    Boş/geçersiz → 300 sn (#273): grounded rapor üretimi (özet/script/asset-story) qwen3:8b'de
    sıcak modelle bile ~3-5 dk; düşük varsayılan ağır yüzeyleri timeout'a düşürürdü.
    """
    if not value or value < 5:
        return 300
    return min(value, 600)


async def save_ai_settings(
    session: AsyncSession,
    *,
    ai_enabled: bool,
    ai_endpoint_url: str,
    ai_model_name: str,
    ai_timeout_sec: int | None,
) -> AppSettings:
    """Yerel AI (OpenAI-uyumlu motor) ayarlarını kaydeder (#182).

    endpoint/model boş bırakılırsa config.py env varsayılanı devreye girer (boş saklanır,
    çözüm anında ``AIConfig.from_app_settings`` doldurur). ai_enabled KAPALI iken AI tamamen
    devre dışıdır (UI butonları görünmez). timeout 5-600 sn'ye kısılır.
    """
    row = await get_settings(session)
    row.ai_enabled = ai_enabled
    row.ai_endpoint_url = (ai_endpoint_url or "").strip()
    row.ai_model_name = (ai_model_name or "").strip()
    row.ai_timeout_sec = normalize_ai_timeout(ai_timeout_sec)
    await session.commit()
    await session.refresh(row)
    set_ai_brand_cache(row.ai_enabled)  # marka modunu anında tazele (Kangalis ↔ Kangalis AI)
    return row


async def probe_ai_endpoint(row: AppSettings) -> dict[str, object]:
    """AI endpoint'ine bağlanıp kurulu modelleri sorgular (Ayarlar > "Bağlantıyı test et").

    Etkin olup olmadığından BAĞIMSIZ test eder (admin etkinleştirmeden önce doğrulayabilsin):
    geçici olarak enabled sayar. Döner: ``ok`` (erişildi mi), ``models`` (kurulu model adları),
    ``has_model`` (yapılandırılan model kurulu mu), ``model`` (çözülen ad).
    """
    from cybersectool.core.ai import AIConfig, list_models

    cfg = AIConfig.from_app_settings(row)
    models = await list_models(AIConfig(True, cfg.endpoint, cfg.model, cfg.timeout))
    if models is None:
        return {"ok": False, "models": [], "has_model": False, "model": cfg.model}
    # Model adlarında ":latest"/quant eki eksik olabilir → gevşek eşleştir (qwen3:8b ≈ qwen3:8b:Q4).
    base = cfg.model.split(":")[0]
    has_model = any(m == cfg.model or m.split(":")[0] == base for m in models)
    return {"ok": True, "models": models, "has_model": has_model, "model": cfg.model}


def get_smtp_password(row: AppSettings) -> str:
    """Şifreli SMTP parolasını çözer (yoksa boş dize)."""
    if not row.smtp_password_encrypted:
        return ""
    return decrypt_secret(row.smtp_password_encrypted)
