"""Web tarayıcı güvenlik başlığı + pasif derinlik + DAST sinyal testleri."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.models import Severity
from cybersectool.scanners.web import (
    COMMON_PATHS,
    check_cookie_flags,
    check_cors,
    check_info_disclosure,
    check_security_headers,
    detect_dir_listing,
    detect_lfi,
    detect_open_redirect,
    detect_sql_error,
    host_matches_names,
    is_interesting_status,
    is_weak_cipher,
    parse_server_banners,
)


def test_parse_server_banners() -> None:
    """SR-3a: Server/X-Powered-By banner → küratörlü (vendor, product, version) üçlüleri."""
    out = parse_server_banners({"Server": "Apache/2.4.49 (Ubuntu)", "X-Powered-By": "PHP/7.4.3"})
    assert ("apache", "http_server", "2.4.49") in out
    assert ("php", "php", "7.4.3") in out
    # nginx + IIS eşlemeleri (NVD vendor/product adlandırması).
    assert parse_server_banners({"server": "nginx/1.18.0"}) == [("nginx", "nginx", "1.18.0")]
    assert parse_server_banners({"Server": "Microsoft-IIS/10.0"}) == [
        ("microsoft", "internet_information_services", "10.0")
    ]
    # Bilinmeyen ürün / sürümsüz banner → atlanır (sahte CVE eşleşmesi önleme).
    assert parse_server_banners({"Server": "CustomServer/1.0"}) == []
    assert parse_server_banners({"Server": "Apache"}) == []  # sürüm yok
    assert parse_server_banners({}) == []


async def test_web_cve_findings_from_banner(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """SR-3a: web banner'ı (Apache/2.4.49) yerel CVE/CPE bankasıyla eşleşince CVE bulgusu üretir."""
    from cybersectool.core.cpe import CpeMatchData, store_cpe_matches
    from cybersectool.core.findings import count_open_findings
    from cybersectool.core.models import CVE, ScanType, Severity
    from cybersectool.core.scans import create_scan
    from cybersectool.tasks.web_scan import _web_cve_findings

    async with session_factory() as session:
        session.add(
            CVE(
                cve_id="CVE-2021-41773",
                description="Apache path traversal",
                cvss_score=7.5,
                severity=Severity.high,
            )
        )
        await session.commit()
        await store_cpe_matches(
            session,
            "CVE-2021-41773",
            [
                CpeMatchData(
                    criteria="cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                    part="a",
                    vendor="apache",
                    product="http_server",
                    version=None,
                    vulnerable=True,
                    version_start_including="2.4.0",
                    version_end_including="2.4.50",
                    version_start_excluding=None,
                    version_end_excluding=None,
                )
            ],
        )
        scan = await create_scan(session, ScanType.web, "http://10.0.0.20")
        # 10.0.0.20 RFC1918 (kapsam içi) → asset+service yolu; banner Apache/2.4.49 eşleşir.
        matched = await _web_cve_findings(
            session, scan.id, "10.0.0.20", 80, "http", {"Server": "Apache/2.4.49"}
        )
        assert matched == ["CVE-2021-41773"]
        assert await count_open_findings(session) == 1


def test_detect_lfi() -> None:
    """#145: /etc/passwd ve win.ini sızıntı imzaları."""
    assert detect_lfi("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:") is True
    assert detect_lfi("; for 16-bit app support\n[fonts]\n[extensions]") is True
    assert detect_lfi("<html>normal sayfa</html>") is False
    assert detect_lfi("root: this is just text") is False  # 0:0: imzası yok


def test_detect_dir_listing() -> None:
    """#145: autoindex (dizin listeleme) tespiti."""
    assert detect_dir_listing("<title>Index of /uploads</title>") is True
    assert detect_dir_listing("Directory listing for /files/") is True
    assert detect_dir_listing("<html>normal app</html>") is False


def test_is_weak_cipher() -> None:
    """#140: zayıf şifre paketleri (RC4/3DES/NULL/EXPORT) + düşük anahtar boyutu."""
    assert is_weak_cipher("ECDHE-RSA-RC4-SHA", 128) is True
    assert is_weak_cipher("DES-CBC3-SHA", 112) is True  # 3DES
    assert is_weak_cipher("ECDHE-RSA-NULL-SHA", 0) is True
    assert is_weak_cipher("EXP-RC2-CBC-MD5", 40) is True
    assert is_weak_cipher("AES128-SHA", 64) is True  # düşük bit
    assert is_weak_cipher("TLS_AES_256_GCM_SHA384", 256) is False  # güçlü
    assert is_weak_cipher("ECDHE-RSA-AES128-GCM-SHA256", 128) is False


def test_host_matches_names() -> None:
    """#140: SAN/CN host eşleşmesi (wildcard dahil); ad yoksa eşleşmiş sayılır (FP önle)."""
    assert host_matches_names({"example.com"}, "example.com") is True
    assert host_matches_names({"*.example.com"}, "api.example.com") is True
    assert host_matches_names({"other.com"}, "example.com") is False
    assert host_matches_names(set(), "example.com") is True
    assert host_matches_names({"*.example.com"}, "example.com") is False  # wildcard kökü kapsamaz


def test_missing_headers_detected() -> None:
    findings = check_security_headers({"content-type": "text/html"})
    assert len(findings) == 5
    titles = [f.title for f in findings]
    assert any("Content-Security-Policy" in t for t in titles)
    assert any("HSTS" in t for t in titles)


def test_present_headers_not_flagged() -> None:
    headers = {
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=63072000",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
    }
    assert check_security_headers(headers) == []


def test_severity_levels() -> None:
    findings = check_security_headers({})
    by_title = {f.title: f.severity for f in findings}
    csp = next(s for t, s in by_title.items() if "Content-Security-Policy" in t)
    xfo = next(s for t, s in by_title.items() if "X-Frame-Options" in t)
    assert csp == Severity.medium
    assert xfo == Severity.low


def test_is_interesting_status() -> None:
    assert is_interesting_status(200) is True
    assert is_interesting_status(403) is True
    assert is_interesting_status(404) is False
    assert is_interesting_status(500) is False


def test_common_paths_include_sensitive() -> None:
    paths = {p for p, _ in COMMON_PATHS}
    assert ".git/config" in paths
    assert ".env" in paths
    # Hassas yollar yüksek önemde
    by_path = dict(COMMON_PATHS)
    assert by_path[".env"] == Severity.high


# --- VI-2: pasif derinlik ---
def test_cookie_flags_missing() -> None:
    findings = check_cookie_flags(["sid=abc; Path=/"])
    assert len(findings) == 1
    assert "Secure" in findings[0].title
    assert "HttpOnly" in findings[0].title
    assert "SameSite" in findings[0].title


def test_cookie_flags_all_present() -> None:
    assert check_cookie_flags(["sid=abc; Secure; HttpOnly; SameSite=Strict"]) == []


def test_cors_wildcard() -> None:
    low = check_cors({"Access-Control-Allow-Origin": "*"})
    assert len(low) == 1 and low[0].severity == Severity.low
    # * + credentials → medium
    med = check_cors(
        {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}
    )
    assert med[0].severity == Severity.medium
    assert check_cors({"Access-Control-Allow-Origin": "https://trusted.example"}) == []


def test_info_disclosure() -> None:
    findings = check_info_disclosure({"Server": "Apache/2.4.49", "X-Powered-By": "PHP/7.4"})
    assert len(findings) == 2
    assert all(f.severity == Severity.info for f in findings)
    assert check_info_disclosure({"Content-Type": "text/html"}) == []


# --- VI-2: aktif DAST sinyalleri (saf) ---
def test_detect_sql_error() -> None:
    assert detect_sql_error("Warning: you have an error in your SQL syntax near ...") is True
    assert detect_sql_error("Unclosed quotation mark after the character string") is True
    assert detect_sql_error("Hoş geldiniz, normal sayfa içeriği") is False


def test_detect_open_redirect() -> None:
    assert detect_open_redirect(302, "https://example.org/kg-open-redirect") is True
    assert detect_open_redirect(200, "https://example.org/kg-open-redirect") is False
    assert detect_open_redirect(302, "/local/path") is False


# --- Dizin/içerik taraması (ayrı kutucuk) ---
def test_dirscan_wordlist_and_severity() -> None:
    from cybersectool.scanners.web import DIRSCAN_WORDLIST, _dirscan_severity

    assert "admin" in DIRSCAN_WORDLIST and ".git" in DIRSCAN_WORDLIST
    assert len(DIRSCAN_WORDLIST) == len(set(DIRSCAN_WORDLIST))  # tekrar eden yol yok
    # Hassas anahtar içeren yol → medium; sıradan → info.
    assert _dirscan_severity(".git/config") == Severity.medium
    assert _dirscan_severity("backup.zip") == Severity.medium
    assert _dirscan_severity("wp-config.php") == Severity.medium
    assert _dirscan_severity("images") == Severity.info


def test_matches_baseline() -> None:
    from cybersectool.scanners.web import _matches_baseline

    baseline = [(200, 1000)]
    # Aynı durum + tolerans içi uzunluk → soft-404 gürültüsü (elenir).
    assert _matches_baseline(baseline, 200, 1000) is True
    assert _matches_baseline(baseline, 200, 1040) is True  # ±64 tolerans
    # Uzunluk farkı tolerans dışı → gerçek yol (elenmez).
    assert _matches_baseline(baseline, 200, 2000) is False
    # Farklı durum kodu → eşleşmez.
    assert _matches_baseline(baseline, 403, 1000) is False
    # Boş taban (normal sunucu) → hiçbir şey elenmez.
    assert _matches_baseline([], 200, 1000) is False


def _patch_mock_transport(monkeypatch: pytest.MonkeyPatch, handler: Callable) -> None:
    """``httpx.AsyncClient``'ı verilen handler'lı MockTransport ile değiştirir (ağsız test)."""
    import httpx

    from cybersectool.scanners import web as webmod

    transport = httpx.MockTransport(handler)
    orig = httpx.AsyncClient

    def patched(*args: object, **kwargs: object) -> httpx.AsyncClient:
        kwargs["transport"] = transport
        return orig(*args, **kwargs)

    monkeypatch.setattr(webmod.httpx, "AsyncClient", patched)


async def test_directory_scan_finds_real_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Var-olmayan yollar 404 (taban boş) → yalnız gerçekten var olan /admin bulgu olur."""
    import httpx

    from cybersectool.scanners.web import DIRSCAN_FINDING_PREFIX, directory_scan

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "kg-" in path:  # baseline probe yolları → yok
            return httpx.Response(404, text="nope")
        if path.endswith("/admin"):
            return httpx.Response(200, text="admin panel")
        return httpx.Response(404, text="nope")

    _patch_mock_transport(monkeypatch, handler)
    findings = await directory_scan("http://t.example", words=["admin", "login", "xyz"])
    titles = [f.title for f in findings]
    assert titles == [f"{DIRSCAN_FINDING_PREFIX} /admin (HTTP 200)"]


async def test_directory_scan_filters_soft_404(monkeypatch: pytest.MonkeyPatch) -> None:
    """Wildcard sunucu HER yola aynı 200'ü döner → taban yakalar, gerçek-yol sonuçları elenir.

    Sessizce BOŞ dönmek yerine durumu açıklayan TEK wildcard bilgi bulgusu eklenir
    (DIRSCAN-FIX: patron "bulgu yok, neden?" yaşıyordu — SPA/Vercel hedefi tüm yollara 200).
    """
    import httpx

    from cybersectool.core.models import Severity
    from cybersectool.scanners.web import (
        DIRSCAN_FINDING_PREFIX,
        DIRSCAN_WILDCARD_TITLE,
        directory_scan,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        # Baseline probe'ları DA gerçek yollar DA aynı 200 + sabit gövde döner.
        return httpx.Response(200, text="<html>fixed soft-404 body</html>")

    _patch_mock_transport(monkeypatch, handler)
    findings = await directory_scan("http://t.example", words=["admin", "login", "backup"])
    # Hiçbir "Bulunan yol:" sonucu yok — hepsi soft-404 gürültüsü olarak elendi.
    assert not [f for f in findings if f.title.startswith(DIRSCAN_FINDING_PREFIX)]
    # ...ama wildcard durumu şeffaflık için TEK info bulgusuyla bildirildi.
    assert [f.title for f in findings] == [DIRSCAN_WILDCARD_TITLE]
    assert findings[0].severity == Severity.info


async def test_directory_scan_wildcard_keeps_distinct_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wildcard sunucuda bile FARKLI imzalı (gerçek) yol elenmemeli; wildcard notu da eklenir."""
    import httpx

    from cybersectool.scanners.web import (
        DIRSCAN_FINDING_PREFIX,
        DIRSCAN_WILDCARD_TITLE,
        directory_scan,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        # /api ayırt edilebilir (farklı durum + gövde); diğer her şey aynı 200 catch-all.
        if request.url.path.endswith("/api"):
            return httpx.Response(403, text="forbidden-distinct")
        return httpx.Response(200, text="<html>fixed soft-404 body</html>")

    _patch_mock_transport(monkeypatch, handler)
    findings = await directory_scan("http://t.example", words=["admin", "api", "login"])
    titles = [f.title for f in findings]
    # Ayırt edilebilen /api bulundu (baseline 200 imzasına uymuyor) + wildcard notu var.
    assert f"{DIRSCAN_FINDING_PREFIX} /api (HTTP 403)" in titles
    assert DIRSCAN_WILDCARD_TITLE in titles
