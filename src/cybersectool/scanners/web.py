"""Web uygulama tarayıcı — güvenlik başlıkları ve TLS/SSL denetimi.

`check_security_headers` saftır (birim testi edilebilir); `fetch_headers` ve `check_tls`
ağ erişimi yapar (e2e ile doğrulanır).
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import socket
import ssl
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx
from cryptography import x509

from cybersectool.core.models import Severity

SECURITY_HEADERS: dict[str, tuple[str, Severity]] = {
    "content-security-policy": ("Content-Security-Policy", Severity.medium),
    "strict-transport-security": ("Strict-Transport-Security (HSTS)", Severity.medium),
    "x-frame-options": ("X-Frame-Options", Severity.low),
    "x-content-type-options": ("X-Content-Type-Options", Severity.low),
    "referrer-policy": ("Referrer-Policy", Severity.low),
}

WEAK_TLS = {"SSLv3", "TLSv1", "TLSv1.1"}

# Zayıf TLS şifre paketi imzaları (RC4/3DES/DES/NULL/EXPORT/MD5/anon) — şifre adında aranır.
WEAK_CIPHER_PATTERNS = ("RC4", "3DES", "DES-", "DES_", "NULL", "EXPORT", "MD5", "ANON", "_ANON")

# Web yığını banner ürün adı → NVD CPE (vendor, product). Yalnız KÜRATÖRLÜ eşlemeler:
# bilinmeyen ürünler atlanır (sahte CVE eşleşmesini önlemek için — yanlış vendor/product
# yüzlerce alakasız CVE getirebilir). Sürüm banner'dan ayrı çıkarılır (SR-3a web CVE tespiti).
_BANNER_CPE_MAP: dict[str, tuple[str, str]] = {
    "apache": ("apache", "http_server"),
    "apache-coyote": ("apache", "tomcat"),
    "tomcat": ("apache", "tomcat"),
    "nginx": ("nginx", "nginx"),
    "microsoft-iis": ("microsoft", "internet_information_services"),
    "iis": ("microsoft", "internet_information_services"),
    "php": ("php", "php"),
    "openssl": ("openssl", "openssl"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "jetty": ("eclipse", "jetty"),
    "mod_ssl": ("modssl", "mod_ssl"),
}

# Banner'da "Ürün/Sürüm" parçalarını yakalar (ör. "Apache/2.4.49", "nginx/1.18.0", "PHP/7.4").
_BANNER_TOKEN_RE = re.compile(r"([A-Za-z][A-Za-z0-9_\-]*)/(\d[\w.]*)")


def parse_server_banners(headers: Mapping[str, str]) -> list[tuple[str, str, str]]:
    """``Server`` + ``X-Powered-By`` başlıklarından (vendor, product, version) üçlüleri çıkarır.

    Yalnız ``_BANNER_CPE_MAP``'te tanımlı küratörlü ürünler döner (sahte eşleşme önleme).
    Sürümü olmayan ya da bilinmeyen ürünler atlanır. SR-3a: web taraması bu üçlüleri yerel
    CVE/CPE bankasıyla eşleştirip web-yığını CVE'lerini bulur (banner→CVE çıkarımı, güvenli).
    """
    out: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    lower = {str(k).lower(): str(v) for k, v in headers.items()}
    for header_name in ("server", "x-powered-by"):
        value = lower.get(header_name)
        if not value:
            continue
        for raw_name, version in _BANNER_TOKEN_RE.findall(value):
            mapping = _BANNER_CPE_MAP.get(raw_name.lower())
            if mapping is None or not version:
                continue
            vendor, product = mapping
            triple = (vendor, product, version)
            if triple not in seen:
                seen.add(triple)
                out.append(triple)
    return out


# Hassas olabilecek yaygın yollar (yol, önem)
COMMON_PATHS: list[tuple[str, Severity]] = [
    (".git/config", Severity.high),
    (".env", Severity.high),
    (".htaccess", Severity.medium),
    ("backup.zip", Severity.medium),
    ("config.php", Severity.medium),
    ("phpinfo.php", Severity.medium),
    ("server-status", Severity.low),
    ("admin", Severity.low),
    ("docs", Severity.info),
]

# "İlginç" (var olan) HTTP durum kodları
INTERESTING_STATUS = {200, 301, 302, 401, 403}

# Dizin taraması bulgusu başlık öneki — rapor/canlı bu önekle dizin bulgularını ayrı
# bölümde gruplar (tek kaynak; değiştirilirse hem üretim hem filtre güncellenmeli).
DIRSCAN_FINDING_PREFIX = "Bulunan yol:"

# Dizin taraması wildcard/catch-all bilgilendirme bulgusu başlığı. Hedef var-olmayan
# yollara da "ilginç" kodla yanıt verince (SPA/Next.js/özel-404/WAF) anlamlı dizin
# ayırt edilemez; bu bulgu durumu şeffaflaştırır (aksi halde tarama sessizce boş döner).
DIRSCAN_WILDCARD_TITLE = "Dizin taraması: hedef tüm yollara yanıt veriyor (catch-all/SPA)"

# Dizin/içerik keşfi kelime listesi (gobuster/dirsearch benzeri). Yaygın dizin + dosya
# adları; erişilebilir olanlar bulgu olur. (Ayrı "Dizin taraması" kutucuğuyla açılır.)
DIRSCAN_WORDLIST: tuple[str, ...] = (
    "admin",
    "administrator",
    "admin.php",
    "admin/login",
    "login",
    "login.php",
    "logout",
    "signin",
    "signup",
    "register",
    "dashboard",
    "panel",
    "cpanel",
    "controlpanel",
    "manage",
    "manager",
    "account",
    "accounts",
    "user",
    "users",
    "profile",
    "settings",
    "config",
    "config.php",
    "configuration",
    "setup",
    "install",
    "installer",
    "update",
    "upgrade",
    "api",
    "api/v1",
    "api/v2",
    "graphql",
    "rest",
    "swagger",
    "swagger-ui",
    "openapi.json",
    "api-docs",
    "v1",
    "v2",
    "app",
    "application",
    "assets",
    "static",
    "public",
    "private",
    "secure",
    "secret",
    "internal",
    "intranet",
    "portal",
    "auth",
    "oauth",
    "sso",
    "token",
    "backup",
    "backups",
    "backup.zip",
    "backup.sql",
    "backup.tar.gz",
    "db",
    "database",
    "db.sql",
    "dump",
    "dump.sql",
    "data",
    "datas",
    "export",
    "import",
    "bin",
    "cgi-bin",
    "lib",
    "libs",
    "vendor",
    "node_modules",
    "src",
    "source",
    "dist",
    "build",
    "tmp",
    "temp",
    "cache",
    "logs",
    "log",
    "error_log",
    "access_log",
    "debug",
    "test",
    "tests",
    "testing",
    "dev",
    "development",
    "staging",
    "stage",
    "demo",
    "sample",
    "examples",
    "old",
    "new",
    "bak",
    "archive",
    "files",
    "file",
    "upload",
    "uploads",
    "download",
    "downloads",
    "media",
    "images",
    "img",
    "css",
    "js",
    "scripts",
    "fonts",
    "docs",
    "doc",
    "documentation",
    "help",
    "support",
    "status",
    "server-status",
    "server-info",
    "health",
    "healthz",
    "metrics",
    "monitor",
    "monitoring",
    "phpmyadmin",
    "pma",
    "adminer",
    "mysql",
    "sql",
    "wp-admin",
    "wp-content",
    "wp-includes",
    "wp-login.php",
    "wp-config.php",
    "xmlrpc.php",
    "robots.txt",
    "sitemap.xml",
    "humans.txt",
    "security.txt",
    ".well-known",
    "crossdomain.xml",
    ".git",
    ".git/config",
    ".gitignore",
    ".svn",
    ".env",
    ".env.local",
    ".htaccess",
    ".htpasswd",
    "web.config",
    ".DS_Store",
    "README",
    "README.md",
    "CHANGELOG",
    "LICENSE",
    "composer.json",
    "package.json",
    "Dockerfile",
    "docker-compose.yml",
    "Makefile",
    ".vscode",
    ".idea",
    "info.php",
    "phpinfo.php",
    "test.php",
    "shell.php",
    "cmd.php",
    "console",
    "actuator",
    "actuator/health",
    "actuator/env",
    "jenkins",
    "gitlab",
    "grafana",
    "kibana",
    "elastic",
)

# Hassas anahtar kelimeler → keşfedilen yol bunları içeriyorsa önem yükseltilir.
_DIRSCAN_SENSITIVE: tuple[str, ...] = (
    "git",
    "svn",
    "env",
    "sql",
    "dump",
    "backup",
    "bak",
    "config",
    "secret",
    "htpasswd",
    "htaccess",
    "web.config",
    "wp-config",
    "phpinfo",
    "ds_store",
    "id_rsa",
    "actuator",
)


# Sürüm/teknoloji açığa çıkaran başlıklar (bilgi ifşası / teknoloji parmak izi)
INFO_HEADERS: tuple[str, ...] = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
)

# Aktif DAST (agresif): tek-tırnak girişine karşı yanıttaki SQL hata imzaları
_SQL_ERROR_SIGNATURES: tuple[str, ...] = (
    "sql syntax",
    "mysql_fetch",
    "you have an error in your sql",
    "ora-0",
    "oracle error",
    "sqlstate",
    "unclosed quotation mark",
    "syntax error at or near",
    "sqlite3.",
    "psqlexception",
    "odbc sql server driver",
    "pg_query",
)
# LFI / path-traversal (#145): dizin-aşımı yükleri ve sızıntı imzaları.
_LFI_PAYLOADS: tuple[str, ...] = (
    "../../../../../../../../etc/passwd",
    "....//....//....//....//....//etc/passwd",
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
)
# LFI denenen yaygın parametre adları (tek istekte hepsine aynı yük gönderilir).
_LFI_PARAMS: tuple[str, ...] = (
    "file",
    "page",
    "path",
    "include",
    "doc",
    "template",
    "lang",
    "view",
)
# /etc/passwd kök satırı imzası (root:x:0:0: gibi).
_PASSWD_RE = re.compile(r"root:[^:]*:0:0:")
# Yansıyan-XSS işaretçisi: escape edilmezse yanıtta ham görünür.
XSS_MARKER = 'kg9x7z"><svg/onload=kg>'


def detect_lfi(body: str) -> bool:
    """Yanıt gövdesi yerel-dosya-dahil (LFI/path traversal) sızıntısı içeriyor mu? (SAF)."""
    if _PASSWD_RE.search(body):
        return True  # /etc/passwd
    low = body.lower()
    return "[extensions]" in low or "[fonts]" in low or "for 16-bit app support" in low  # win.ini


def detect_dir_listing(body: str) -> bool:
    """Yanıt gövdesi dizin listeleme (autoindex) gösteriyor mu? (SAF)."""
    low = body.lower()
    return "index of /" in low or "directory listing for" in low or "<title>index of" in low


# Açık-yönlendirme testinde kullanılan zararsız hedef (RFC 2606 / IANA örnek alan).
REDIR_MARKER = "example.org/kg-open-redirect"


@dataclass
class WebFinding:
    title: str
    severity: Severity
    description: str | None = None


@dataclass
class PageResult:
    status: int
    headers: dict[str, str]
    set_cookie: list[str]
    body: str


async def fetch_page(url: str) -> PageResult | None:
    """URL'yi GET eder; başlık + Set-Cookie listesi + gövde (kırpılmış) döner. Hata'da None."""
    # SSRF/scope-kaçağı koruması: yönlendirmeleri TAKİP ETME. İstek doğrulanan IP'ye pinlenir;
    # bir 302 iç servise / bulut-metadata'ya (169.254.169.254) yönlendirip IP-pin scope guard'ını
    # atlatabilirdi. Aktif problar zaten follow_redirects=False — pasif fetch de hizalanır.
    try:
        async with httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=False) as client:
            resp = await client.get(url)
        return PageResult(
            status=resp.status_code,
            headers={key.lower(): value for key, value in resp.headers.items()},
            set_cookie=list(resp.headers.get_list("set-cookie")),
            body=resp.text[:200_000],
        )
    except httpx.HTTPError:
        return None


def check_cookie_flags(set_cookie_values: list[str]) -> list[WebFinding]:
    """Set-Cookie başlıklarında eksik Secure/HttpOnly/SameSite bayraklarını bulgular (pasif)."""
    findings: list[WebFinding] = []
    for raw in set_cookie_values:
        attrs = raw.lower()
        name = raw.split("=", 1)[0].strip() or "?"
        missing = [
            flag
            for flag, token in (
                ("Secure", "secure"),
                ("HttpOnly", "httponly"),
                ("SameSite", "samesite"),
            )
            if token not in attrs
        ]
        if missing:
            findings.append(
                WebFinding(
                    title=f"Çerez güvenlik bayrağı eksik: {name} ({', '.join(missing)})",
                    severity=Severity.low,
                    description=f"Çerez {', '.join(missing)} bayrağı olmadan ayarlanmış.",
                )
            )
    return findings


def check_cors(headers: Mapping[str, str]) -> list[WebFinding]:
    """Geniş/yanlış yapılandırılmış CORS politikasını bulgular (pasif)."""
    h = {key.lower(): value for key, value in headers.items()}
    acao = h.get("access-control-allow-origin")
    acac = (h.get("access-control-allow-credentials") or "").lower()
    if acao == "*":
        with_creds = acac == "true"
        return [
            WebFinding(
                title="Geniş CORS politikası (Access-Control-Allow-Origin: *)",
                severity=Severity.medium if with_creds else Severity.low,
                description=(
                    "Tüm kökenler erişebiliyor; kimlik bilgileriyle birlikte yüksek risk."
                    if with_creds
                    else "Tüm kökenler bu kaynağa erişebiliyor."
                ),
            )
        ]
    return []


def check_info_disclosure(headers: Mapping[str, str]) -> list[WebFinding]:
    """Sürüm/teknoloji açığa çıkaran başlıkları bulgular (pasif parmak izi)."""
    h = {key.lower(): value for key, value in headers.items()}
    findings: list[WebFinding] = []
    for key in INFO_HEADERS:
        value = h.get(key)
        if value:
            findings.append(
                WebFinding(
                    title=f"Bilgi ifşası: {key} → {value}",
                    severity=Severity.info,
                    description=f"'{key}' başlığı sunucu/teknoloji bilgisini açığa çıkarıyor.",
                )
            )
    return findings


def detect_sql_error(body: str) -> bool:
    """Yanıt gövdesinde bilinen bir SQL hata imzası var mı (hata-tabanlı SQLi sinyali)."""
    low = body.lower()
    return any(sig in low for sig in _SQL_ERROR_SIGNATURES)


def detect_open_redirect(status: int, location: str) -> bool:
    """3xx + Location enjekte edilen dış hedefe gidiyorsa açık yönlendirme."""
    return status in (301, 302, 303, 307, 308) and REDIR_MARKER in location


async def active_dast(url: str) -> list[WebFinding]:
    """Agresif aktif DAST: yansıyan-XSS / hata-tabanlı SQLi / açık-yönlendirme (kapılı).

    Az sayıda zararsız işaretçi gönderir; yalnızca NET sinyalde bulgu üretir (düşük FP).
    Yalnızca agresif mod + 'kabul ediyorum' onayıyla çağrılır.
    """
    findings: list[WebFinding] = []
    async with httpx.AsyncClient(timeout=12.0, verify=False, follow_redirects=False) as client:
        try:
            r = await client.get(url, params={"kgq": XSS_MARKER})
            if XSS_MARKER in r.text:
                findings.append(
                    WebFinding(
                        "Olası yansıyan XSS (DAST aktif)",
                        Severity.high,
                        "Enjekte edilen işaretçi yanıtta escape edilmeden yansıdı.",
                    )
                )
        except httpx.HTTPError:
            pass
        try:
            r = await client.get(url, params={"kgq": "'"})
            if detect_sql_error(r.text):
                findings.append(
                    WebFinding(
                        "Olası SQL enjeksiyonu (DAST aktif, hata-tabanlı)",
                        Severity.high,
                        "Tek tırnak girişi yanıtta SQL hata imzası üretti.",
                    )
                )
        except httpx.HTTPError:
            pass
        try:
            redir = f"https://{REDIR_MARKER}"
            r = await client.get(
                url, params={"next": redir, "url": redir, "redirect": redir, "return": redir}
            )
            if detect_open_redirect(r.status_code, r.headers.get("location", "")):
                findings.append(
                    WebFinding(
                        "Olası açık yönlendirme (DAST aktif)",
                        Severity.medium,
                        "Yönlendirme parametresi dış adrese yönlendiriyor.",
                    )
                )
        except httpx.HTTPError:
            pass
        # LFI / path traversal (#145): dizin-aşımı yükü sistem dosyası döndürürse bulgu.
        for payload in _LFI_PAYLOADS:
            try:
                r = await client.get(url, params=dict.fromkeys(_LFI_PARAMS, payload))
            except httpx.HTTPError:
                continue
            if detect_lfi(r.text):
                findings.append(
                    WebFinding(
                        "Olası yerel dosya dahil etme / path traversal (DAST aktif)",
                        Severity.high,
                        "Dizin-aşımı yükü yanıtta sistem dosyası (/etc/passwd ya da win.ini) "
                        "içeriği döndürdü.",
                    )
                )
                break
        # Dizin listeleme (autoindex) — hedef yanıtı dizin içeriğini listeliyor mu.
        try:
            r = await client.get(url)
            if detect_dir_listing(r.text):
                findings.append(
                    WebFinding(
                        "Dizin listeleme açık (autoindex)",
                        Severity.medium,
                        "Sunucu dizin içeriğini listeliyor (Index of /) — dosya/yol keşfini "
                        "kolaylaştırır.",
                    )
                )
        except httpx.HTTPError:
            pass
    return findings


def check_security_headers(headers: Mapping[str, str]) -> list[WebFinding]:
    """Eksik güvenlik başlıklarını bulgu olarak döndürür."""
    present = {key.lower() for key in headers}
    findings: list[WebFinding] = []
    for key, (label, severity) in SECURITY_HEADERS.items():
        if key not in present:
            findings.append(
                WebFinding(
                    title=f"Eksik güvenlik başlığı: {label}",
                    severity=severity,
                    description=f"HTTP yanıtı '{label}' başlığını içermiyor.",
                )
            )
    return findings


async def fetch_headers(url: str) -> dict[str, str] | None:
    """URL'nin HTTP yanıt başlıklarını (küçük harfli) döndürür. Hata'da None."""
    # SSRF/scope-kaçağı koruması: yönlendirme TAKİP EDİLMEZ (bkz. fetch_page). 302 ile pinlenen
    # IP'den iç servise/metadata'ya sıçramayı engeller.
    try:
        async with httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=False) as client:
            resp = await client.get(url)
            return {key.lower(): value for key, value in resp.headers.items()}
    except httpx.HTTPError:
        return None


def is_interesting_status(status_code: int) -> bool:
    """Bir yolun var olduğunu (erişilebilir ya da korumalı) gösteren durum kodu mu?"""
    return status_code in INTERESTING_STATUS


async def check_common_paths(base_url: str) -> list[WebFinding]:
    """Yaygın hassas yolları prob eder; var olanları bulgu olarak döndürür."""
    findings: list[WebFinding] = []
    base = base_url.rstrip("/")
    async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=False) as client:
        for path, severity in COMMON_PATHS:
            try:
                resp = await client.get(f"{base}/{path}")
            except httpx.HTTPError:
                continue
            if is_interesting_status(resp.status_code):
                findings.append(
                    WebFinding(
                        title=f"Erişilebilir yol: /{path} (HTTP {resp.status_code})",
                        severity=severity,
                        description="Hassas olabilecek bir yol erişilebilir görünüyor.",
                    )
                )
    return findings


def _dirscan_severity(path: str) -> Severity:
    """Keşfedilen yolun önem derecesi: hassas anahtar içeriyorsa medium, değilse info."""
    low = path.lower()
    return Severity.medium if any(key in low for key in _DIRSCAN_SENSITIVE) else Severity.info


# Tek dizin taramasında denenecek azami kelime sayısı (hedefi sel altında bırakmamak için).
MAX_DIRSCAN_WORDS = 10_000

# Soft-404/wildcard tespiti için var olmayan rastgele yollar. Bunlar "ilginç" bir kodla
# dönerse sunucu her yola yanıt veriyordur → o yanıt imzaları taban (baseline) sayılır.
_DIRSCAN_BASELINE_PROBES: tuple[str, ...] = (
    "kg-nonexistent-a7f3c9e1b2",
    "kg-404-probe-9b2d4f6a8c",
    "kg-not-here-x82k1q5w3e",
)
# Taban gövde uzunluğuyla eşleşme toleransı (özel 404 sayfası yola göre az değişebilir).
_DIRSCAN_LEN_TOLERANCE = 64


async def _dirscan_baseline(client: httpx.AsyncClient, base: str) -> list[tuple[int, int]]:
    """Rastgele var-olmayan yolları prob eder; "ilginç" dönenlerin (durum, gövde-uzunluğu)
    imzasını taban olarak döndürür. Normal sunucuda (404) liste BOŞ kalır → filtre devre dışı.
    """
    baseline: list[tuple[int, int]] = []
    for probe in _DIRSCAN_BASELINE_PROBES:
        try:
            resp = await client.get(f"{base}/{probe}")
        except httpx.HTTPError:
            continue
        if is_interesting_status(resp.status_code):
            baseline.append((resp.status_code, len(resp.content)))
    return baseline


def _matches_baseline(baseline: list[tuple[int, int]], status: int, length: int) -> bool:
    """Yanıt, wildcard/soft-404 tabanına (aynı durum + benzer uzunluk) uyuyor mu?"""
    return any(
        b_status == status and abs(b_len - length) <= _DIRSCAN_LEN_TOLERANCE
        for b_status, b_len in baseline
    )


async def directory_scan(
    base_url: str,
    words: tuple[str, ...] | list[str] | None = None,
    concurrency: int = 12,
) -> list[WebFinding]:
    """Kelime listesiyle dizin/içerik keşfi (gobuster benzeri); erişilebilir yolları döndürür.

    Eşzamanlı (sınırlı) GET ile her kelimeyi dener; "ilginç" durum koduna (200/301/302/
    401/403) sahip yollar bulgu olur. ``words`` verilmezse yerleşik ``DIRSCAN_WORDLIST``
    kullanılır. Yalnız ``dir_scan`` işaretliyse çağrılır.

    DOĞRULUK: önce rastgele var-olmayan yollar prob edilir; sunucu bunlara "ilginç" bir
    kodla yanıt veriyorsa (SPA/özel-404/wildcard) o imzalar taban sayılır ve eşleşen
    sonuçlar elenir — böylece "her yol bulundu" yanlış-pozitif seli önlenir. Normal
    sunucuda taban boştur ve davranış değişmez.
    """
    base = base_url.rstrip("/")
    raw = list(words) if words is not None else list(DIRSCAN_WORDLIST)
    paths = raw[:MAX_DIRSCAN_WORDS]
    sem = asyncio.Semaphore(concurrency)
    findings: list[WebFinding] = []

    async def _probe(client: httpx.AsyncClient, path: str, baseline: list[tuple[int, int]]) -> None:
        async with sem:
            try:
                resp = await client.get(f"{base}/{path}")
            except httpx.HTTPError:
                return
        if not is_interesting_status(resp.status_code):
            return
        if _matches_baseline(baseline, resp.status_code, len(resp.content)):
            return  # soft-404/wildcard gürültüsü — gerçek bir yol değil
        findings.append(
            WebFinding(
                title=f"{DIRSCAN_FINDING_PREFIX} /{path} (HTTP {resp.status_code})",
                severity=_dirscan_severity(path),
                description="Dizin/içerik keşfiyle erişilebilir bir yol bulundu.",
            )
        )

    async with httpx.AsyncClient(timeout=6.0, verify=False, follow_redirects=False) as client:
        baseline = await _dirscan_baseline(client, base)
        await asyncio.gather(*(_probe(client, path, baseline) for path in paths))
    findings.sort(key=lambda f: f.title)
    if baseline:
        # Hedef var-olmayan yollara da yanıt verdi (catch-all/SPA/özel-404/WAF) → eşleşen
        # yollar elendi. Aksi halde tarama SESSİZCE boş döner ("bulgu yok, neden?"); bu
        # bilgi bulgusu durumu açıklar (gerçekten ayırt edilebilen yollar yine listelenir).
        statuses = ", ".join(sorted({f"HTTP {s}" for s, _ in baseline}))
        findings.append(
            WebFinding(
                title=DIRSCAN_WILDCARD_TITLE,
                severity=Severity.info,
                description=(
                    "Hedef, var olmayan rastgele yollara da 'başarılı' bir kodla "
                    f"({statuses}) yanıt veriyor. Bu, tek-sayfa uygulaması (SPA/Next.js), "
                    "özel 404 sayfası ya da WAF/proxy davranışıdır; tüm yollar aynı imzaya "
                    "düştüğü için klasik dizin/içerik keşfi bu hedefte gizli dizinleri "
                    "ayırt edemez. Ayırt edilebilen yollar (farklı imza) yine raporlanır."
                ),
            )
        )
    return findings


def is_weak_cipher(name: str, bits: int) -> bool:
    """Şifre paketi adı/anahtar boyutuna göre zayıf mı? (SAF — test edilebilir)."""
    upper = (name or "").upper()
    if any(p in upper for p in WEAK_CIPHER_PATTERNS):
        return True
    return bool(bits) and bits < 128


def host_matches_names(names: set[str], host: str) -> bool:
    """Sertifika SAN/CN adları host ile eşleşiyor mu? (wildcard dahil; SAF — test edilebilir).

    Hiç ad yoksa True döner (eşleşme yok diyemeyiz → yanlış-pozitif önlenir).
    """
    if not names:
        return True
    for n in names:
        if n == host:
            return True
        if n.startswith("*.") and host.split(".", 1)[-1] == n[2:]:
            return True
    return False


def _unverified_context() -> ssl.SSLContext:
    """Doğrulamasız TLS context — self-signed/expired sertifikada da handshake tamamlanır.

    create_default_context() sertifikayı DOĞRULAR → self-signed/expired handshake'i düşürür ve
    ardından gelen protokol/cipher denetimleri HİÇ çalışmazdı (#140). CERT_NONE ile bağlanıp
    sertifikayı AYRICA denetleriz.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _cert_names(cert: x509.Certificate) -> set[str]:
    names: set[str] = set()
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names.update(san.get_values_for_type(x509.DNSName))
        names.update(str(ip) for ip in san.get_values_for_type(x509.IPAddress))
    except x509.ExtensionNotFound:
        pass
    try:
        for attr in cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME):
            names.add(str(attr.value))
    except Exception:
        pass
    return names


def _check_cert(der: bytes | None, host: str) -> list[WebFinding]:
    """DER sertifikadan süre/self-signed/host-uyuşmazlığı bulgularını çıkarır (cryptography)."""
    out: list[WebFinding] = []
    if not der:
        return out
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return out
    try:
        not_after = cert.not_valid_after_utc
        days = (not_after - datetime.now(UTC)).days
        if days < 0:
            out.append(WebFinding("TLS sertifikası süresi dolmuş", Severity.high))
        elif days < 30:
            out.append(WebFinding(f"TLS sertifikası {days} gün içinde dolacak", Severity.low))
    except Exception:
        pass
    if cert.issuer == cert.subject:
        out.append(WebFinding("Kendinden imzalı (self-signed) TLS sertifikası", Severity.medium))
    if not host_matches_names(_cert_names(cert), host):
        out.append(WebFinding(f"TLS sertifikası host adıyla uyuşmuyor: {host}", Severity.medium))
    return out


def _protocol_enabled(host: str, port: int, proto: ssl.TLSVersion) -> bool:
    """Hedef belirtilen zayıf TLS protokolünü ETKİN kabul ediyor mu? (handshake denemesi)."""
    ctx = _unverified_context()
    try:
        ctx.minimum_version = proto
        ctx.maximum_version = proto
    except (ValueError, OSError):
        return False  # bu Python/OpenSSL protokolü desteklemiyor → test edilemez
    # Modern OpenSSL (3.x, SECLEVEL≥2) TLSv1.0/1.1 + eski cipher'ları İSTEMCİ tarafında reddeder
    # → sunucu zayıf protokolü açık tutsa bile handshake başlamadan düşer = YANLIŞ-NEGATİF.
    # Güvenlik seviyesini bu prob için düşür ki eski protokol gerçekten test edilebilsin
    # (yalnız tespit amaçlı; aracın kendi TLS'i etkilenmez).
    with contextlib.suppress(ssl.SSLError):
        # bu OpenSSL derlemesi SECLEVEL=0'ı kabul etmezse eldeki cipher'larla devam (best-effort)
        ctx.set_ciphers("DEFAULT@SECLEVEL=0")
    try:
        with (
            socket.create_connection((host, port), timeout=8) as sock,
            ctx.wrap_socket(sock, server_hostname=host),
        ):
            return True
    except (ssl.SSLError, OSError):
        return False


def check_tls(host: str, port: int = 443) -> list[WebFinding]:
    """TLS sürümü + şifre paketi + sertifika denetimi (bloklayan; thread'de çağrılmalı).

    Doğrulamasız bağlanır (self-signed/expired'da bile handshake tamamlanır), görüşülen
    protokol + cipher'ı denetler, sertifikayı ayrıca analiz eder (süre/self-signed/host) ve
    zayıf protokollerin (TLSv1.0/1.1) ETKİN olup olmadığını ayrı handshake'lerle yoklar (#140).
    """
    findings: list[WebFinding] = []
    ctx = _unverified_context()
    try:
        with (
            socket.create_connection((host, port), timeout=10) as sock,
            ctx.wrap_socket(sock, server_hostname=host) as tls_sock,
        ):
            version = tls_sock.version()
            cipher = tls_sock.cipher()
            der = tls_sock.getpeercert(binary_form=True)
    except (ssl.SSLError, OSError) as exc:
        return [WebFinding("TLS/SSL bağlantı hatası", Severity.medium, str(exc))]

    if version in WEAK_TLS:
        findings.append(WebFinding(f"Zayıf TLS sürümü (görüşülen): {version}", Severity.medium))
    if cipher:
        cname, _, cbits = cipher
        if is_weak_cipher(cname or "", int(cbits or 0)):
            findings.append(
                WebFinding(f"Zayıf TLS şifre paketi: {cname} ({cbits} bit)", Severity.medium)
            )

    findings.extend(_check_cert(der, host))

    for proto, label in (
        (ssl.TLSVersion.TLSv1, "TLSv1.0"),
        (ssl.TLSVersion.TLSv1_1, "TLSv1.1"),
    ):
        if _protocol_enabled(host, port, proto):
            findings.append(WebFinding(f"Zayıf TLS protokolü ETKİN: {label}", Severity.high))
    return findings
