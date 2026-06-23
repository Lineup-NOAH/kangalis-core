"""Güvenlik sertleştirme turu (2026-06 denetimi kapanışı):

- #5 SSRF metadata-guard (``core.net_guard.is_blocked_url``) — link-local/metadata literal IP bloğu
- #6 MCP fail-closed (``mcp.rbac.is_parseable_jsonrpc``) — bozuk JSON-RPC gövdesi reddedilir
- #2 CSRF Origin/Referer kontrolü (``api.app`` middleware) — cookie istekleri için aynı-köken
- #4 CSP başlığı varlığı
- #2b logout yalnız POST (GET kaldırıldı → logout-CSRF kapandı)

(Web-scanner redirect-SSRF, #1, davranışsal olarak ``scanners/web.py``'de follow_redirects=False ile
doğrudan kapandı; ayrı testi yok — pasif fetch artık aktif problarla aynı.)
"""

from __future__ import annotations

import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.models import Role
from cybersectool.core.net_guard import is_blocked_url
from cybersectool.core.users import create_user
from cybersectool.mcp.rbac import is_parseable_jsonrpc
from cybersectool.scanners.web import fetch_headers, fetch_page

# --- #5 net_guard: link-local/bulut-metadata literal IP bloğu (RFC1918/hostname meşru) ---


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",  # AWS/GCP/Azure metadata
        "http://169.254.0.1:8080/x",
        "https://[fe80::1]/y",  # IPv6 link-local
        "http://[::ffff:169.254.169.254]/meta",  # IPv4-eşlemli IPv6 atlatması da yakalanır
        "http://2852039166/meta",  # ondalık-kodlu 169.254.169.254 (yeniden-kodlama atlatması)
        "http://0xA9FEA9FE/meta",  # hex-kodlu 169.254.169.254
        "http://0251.0376.0251.0376/meta",  # oktal-kodlu 169.254.169.254
        "http://169.254.169.254./meta",  # sondaki nokta (FQDN) — normalize edilip yakalanır
        "http://user@169.254.169.254/meta",  # userinfo ile gizleme — host yine 169.254.x
    ],
)
def test_net_guard_blocks_link_local(url: str) -> None:
    assert is_blocked_url(url) is True


@pytest.mark.parametrize(
    "url",
    [
        "http://ollama:11434/v1/chat/completions",  # yerel AI motoru (hostname) — meşru
        "https://api.github.com/repos/x/releases/latest",  # dış güncelleme — meşru
        "http://192.168.1.10:11434/v1",  # RFC1918 özel-ağ motor/ayna — meşru
        "http://10.0.0.5/mirror",  # RFC1918 iç-ayna — meşru
        "http://127.0.0.1:11434/v1",  # loopback yerel motor — engellenmez (meşru)
        "not a url",
        "",
    ],
)
def test_net_guard_allows_legit(url: str) -> None:
    assert is_blocked_url(url) is False


# --- #6 MCP fail-closed: boş-olmayan geçersiz JSON-RPC gövdesi reddedilir ---


def test_jsonrpc_parseable_accepts_empty_and_valid() -> None:
    assert is_parseable_jsonrpc(b"") is True  # boş (GET/SSE) → dokunulmaz
    assert is_parseable_jsonrpc(b'{"method":"tools/list"}') is True


def test_jsonrpc_parseable_rejects_malformed() -> None:
    assert is_parseable_jsonrpc(b"{bozuk json") is False  # fail-closed
    assert is_parseable_jsonrpc(b"\xff\xfe rastgele baytlar") is False


# --- #2 CSRF: Origin/Referer aynı-köken kontrolü (cookie/oturum istekleri) ---


async def test_csrf_blocks_cross_origin_post(client: AsyncClient) -> None:
    """Çapraz-köken (Origin != app host) durum-değiştiren POST → 403 (CSRF)."""
    resp = await client.post(
        "/auth/login",
        json={"username": "x", "password": "y"},
        headers={"origin": "http://evil.example"},
    )
    assert resp.status_code == 403
    assert "CSRF" in resp.json()["detail"]


async def test_csrf_blocks_cross_origin_via_referer(client: AsyncClient) -> None:
    """Origin yok ama Referer çapraz-köken → yine 403 (Referer fallback)."""
    resp = await client.post(
        "/auth/login",
        json={"username": "x", "password": "y"},
        headers={"referer": "http://evil.example/login"},
    )
    assert resp.status_code == 403


async def test_csrf_allows_same_origin_post(client: AsyncClient) -> None:
    """Aynı-köken POST CSRF'e takılmaz (auth mantığına geçer → 401, 403-CSRF DEĞİL)."""
    resp = await client.post(
        "/auth/login",
        json={"username": "x", "password": "y"},
        headers={"origin": "http://test"},  # conftest base_url netloc = 'test'
    )
    assert resp.status_code != 403


async def test_csrf_allows_missing_origin(client: AsyncClient) -> None:
    """Origin/Referer yoksa izin verilir — çapraz-köken tarayıcı saldırısı bu durumu üretemez."""
    resp = await client.post("/auth/login", json={"username": "x", "password": "y"})
    assert resp.status_code != 403


async def test_csrf_exempts_bearer_token(client: AsyncClient) -> None:
    """Bearer (programatik) istek kötü Origin ile bile CSRF'ten MUAF (cookie yok = CSRF yok)."""
    resp = await client.post(
        "/scans",
        json={"target": "10.0.0.1", "scan_type": "network", "mode": "safe"},
        headers={"origin": "http://evil.example", "authorization": "Bearer cst_invalid"},
    )
    assert resp.status_code == 401  # geçersiz token (CSRF 403 değil)


async def test_csrf_ignores_safe_get(client: AsyncClient) -> None:
    """GET güvenli metot — çapraz-köken Origin'le bile CSRF kontrolü uygulanmaz."""
    resp = await client.get("/login", headers={"origin": "http://evil.example"})
    assert resp.status_code == 200


async def test_csrf_blocks_origin_null(client: AsyncClient) -> None:
    """``Origin: null`` (sandbox iframe / data: kökeni) host'a çözülemez → 403."""
    resp = await client.post(
        "/auth/login",
        json={"username": "x", "password": "y"},
        headers={"origin": "null"},
    )
    assert resp.status_code == 403


# --- #4 CSP başlığı varlığı + sertleştirme direktifleri ---


async def test_csp_header_present(client: AsyncClient) -> None:
    resp = await client.get("/login")
    csp = resp.headers.get("content-security-policy", "")
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "object-src 'none'" in csp
    assert "base-uri 'self'" in csp


# --- #2b logout yalnız POST ---


async def test_logout_get_removed_post_works(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    async with session_factory() as s:
        await create_user(s, "admin1", "pass1234", role=Role.admin)
    await client.post("/login", data={"username": "admin1", "password": "pass1234"})
    # GET /logout artık yok → 405; POST /logout login'e yönlendirir (303).
    get_resp = await client.get("/logout", follow_redirects=False)
    assert get_resp.status_code == 405
    post_resp = await client.post(
        "/logout", headers={"origin": "http://test"}, follow_redirects=False
    )
    assert post_resp.status_code in (302, 303)


# --- #1 web-scanner redirect-SSRF: pasif fetch'ler yönlendirme TAKİP ETMEZ ---


async def test_web_passive_fetch_no_follow_redirects(monkeypatch: pytest.MonkeyPatch) -> None:
    """fetch_page + fetch_headers httpx istemcisini follow_redirects=False ile kurar.

    Bir 302 takip edilseydi, pinlenen IP'den iç servise/bulut-metadata'ya sıçranabilirdi
    (scope/IP-pin atlatması). Burada istemci yapım parametresini doğrudan doğrularız.
    """
    seen: list[object] = []
    real_init = httpx.AsyncClient.__init__

    def spy_init(self: httpx.AsyncClient, *args: object, **kwargs: object) -> None:
        seen.append(kwargs.get("follow_redirects"))
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", spy_init)
    # Kapalı port → bağlantı reddedilir → None döner; ama istemci zaten kurulmuştur.
    await fetch_page("http://127.0.0.1:9/")
    await fetch_headers("http://127.0.0.1:9/")
    assert seen == [False, False]


# --- #3 defusedxml: libnmap XML ayrıştırıcı XXE/billion-laughs güvenli ---


def test_libnmap_uses_defused_parser() -> None:
    """python-libnmap, defusedxml kuruluysa onu otomatik seçer → nmap XML ayrıştırma XXE-güvenli.

    Koruma libnmap'in opsiyonel ``try: import defusedxml.ElementTree`` davranışıyla gelir; bu
    test onu örtük-yan-etki olmaktan çıkarıp açıkça sabitler (bağımlılık düşerse kırmızı yanar).
    """
    import libnmap.parser

    assert "defusedxml" in libnmap.parser.ET.__name__
