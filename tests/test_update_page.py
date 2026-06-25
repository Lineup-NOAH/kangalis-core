"""Güncelleme sayfası (/update) — admin-gating, render, 'şimdi denetle', ayar kaydı.

Egress (run_update_check) httpx mock'lanır → gerçek ağ yok. Versiyon probe'ları (nmap/redis)
test ortamında deterministik olsun diye monkeypatch'lenir.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import cybersectool
import cybersectool.core.update_check as uc
import cybersectool.core.versions as ver
from cybersectool.core.app_settings import get_settings
from cybersectool.core.models import Role
from cybersectool.core.users import create_user


async def _login(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    username: str,
    role: Role,
) -> None:
    async with session_factory() as s:
        await create_user(s, username, "pass1234", role=role)
    await client.post(
        "/login", data={"username": username, "password": "pass1234"}, follow_redirects=False
    )


def _fast_versions(monkeypatch: pytest.MonkeyPatch, *, nmap: str | None = "7.94") -> None:
    """nmap/redis probe'larını deterministik + hızlı yapar (dış bağımlılık olmasın)."""
    monkeypatch.setattr(ver, "nmap_version", lambda: nmap)

    async def _no_redis() -> None:
        return None

    monkeypatch.setattr(ver, "redis_version", _no_redis)


async def test_update_page_admin_renders(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Admin /update'i görür: başlık + sürüm + sürüm tablosu + uygulama komutu render olur."""
    _fast_versions(monkeypatch)
    await _login(client, session_factory, "adm_upd", Role.admin)
    resp = await client.get("/update")
    assert resp.status_code == 200
    body = resp.text
    assert "Güncelleme" in body  # başlık + nav
    assert f"v{cybersectool.__version__}" in body  # yüklü sürüm
    assert "Sürüm Bilgisi" in body  # versiyon kartı
    assert "docker compose pull" in body  # uygulama komutu (host'ta)
    assert "7.94" in body  # nmap sürüm satırı
    assert 'href="/update"' in body  # sol menü girişi


async def test_update_page_non_admin_redirect(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Admin olmayan kullanıcı /update'ten ana sayfaya yönlendirilir."""
    await _login(client, session_factory, "an_upd", Role.analyst)
    resp = await client.get("/update", follow_redirects=False)
    assert resp.status_code in (302, 303)
    assert resp.headers.get("location") == "/"


async def test_update_requires_login(client: AsyncClient) -> None:
    """Giriş yapılmadan /update login'e yönlendirir."""
    resp = await client.get("/update", follow_redirects=False)
    assert resp.status_code in (302, 303)
    assert "login" in resp.headers.get("location", "").lower()


async def test_update_check_now_posts_and_redirects(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """'Şimdi denetle' POST → denetim çalışır (mock egress) → /update?msg=checked'e döner."""

    class _Resp:
        status_code = 404

        def json(self) -> dict:
            return {}

    class _Client:
        async def __aenter__(self) -> _Client:
            return self

        async def __aexit__(self, *_: object) -> bool:
            return False

        async def get(self, url: str, headers: dict | None = None) -> _Resp:
            return _Resp()

    monkeypatch.setattr(uc.httpx, "AsyncClient", lambda *a, **k: _Client())
    await _login(client, session_factory, "adm_chk", Role.admin)
    resp = await client.post("/update/check", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers.get("location") == "/update?msg=checked"


async def test_update_check_now_requires_admin(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Admin olmayan kullanıcı 'şimdi denetle' POST'unu tetikleyemez (ana sayfaya yönlenir)."""
    await _login(client, session_factory, "an_chk", Role.analyst)
    resp = await client.post("/update/check", follow_redirects=False)
    assert resp.status_code in (302, 303)
    assert resp.headers.get("location") == "/"


async def test_update_settings_saved_and_url_validated(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Ayar kaydı: enabled saklanır; geçersiz şemalı URL (ftp://) varsayılana düşer (SSRF/şema)."""
    await _login(client, session_factory, "adm_set", Role.admin)
    resp = await client.post(
        "/update/settings",
        data={"update_check_enabled": "true", "update_check_url": "ftp://evil/x"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers.get("location") == "/update?msg=saved"
    async with session_factory() as s:
        row = await get_settings(s)
    assert row.update_check_enabled is True
    assert row.update_check_url.startswith("https://api.github.com")  # ftp:// reddedildi → default


async def test_update_settings_disable(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Checkbox işaretsiz gönderilince otomatik denetim kapanır (egress kapatılabilir)."""
    await _login(client, session_factory, "adm_dis", Role.admin)
    resp = await client.post(
        "/update/settings",
        data={"update_check_url": "https://api.github.com/repos/x/y/releases/latest"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    async with session_factory() as s:
        row = await get_settings(s)
    assert row.update_check_enabled is False
