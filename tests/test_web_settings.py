"""Ayarlar (/settings) web sayfası testleri — admin-only render + kaydetme + RBAC."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.app_settings import get_nvd_api_key, get_settings
from cybersectool.core.models import Role
from cybersectool.core.users import create_user


async def _login(
    client: AsyncClient,
    factory: async_sessionmaker[AsyncSession],
    username: str,
    role: Role = Role.admin,
) -> None:
    async with factory() as session:
        await create_user(session, username, "pass1234", role=role)
    await client.post("/auth/login", json={"username": username, "password": "pass1234"})


async def test_settings_page_admin_renders(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "adm", Role.admin)
    resp = await client.get("/settings")
    assert resp.status_code == 200
    assert "Ayarlar" in resp.text


async def test_settings_page_non_admin_redirect(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "an", Role.analyst)
    resp = await client.get("/settings", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/"


async def test_settings_anonymous_redirect(client: AsyncClient) -> None:
    resp = await client.get("/settings", follow_redirects=False)
    assert resp.status_code == 303


async def test_settings_ratelimit_save(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "adm2", Role.admin)
    resp = await client.post(
        "/settings/ratelimit",
        data={"enabled": "on", "max_attempts": "7", "window_sec": "120", "lockout_sec": "600"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    async with session_factory() as session:
        s = await get_settings(session)
        assert s.ratelimit_enabled is True
        assert s.ratelimit_max_attempts == 7
        assert s.ratelimit_window_sec == 120
        assert s.ratelimit_lockout_sec == 600


async def test_settings_smtp_save_encrypts(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "adm3", Role.admin)
    resp = await client.post(
        "/settings/smtp",
        data={
            "enabled": "on",
            "host": "smtp.corp",
            "port": "465",
            "username": "mailer",
            "password": "p@ss",
            "sender": "kg@corp",
            "alert_to": "soc@corp",
            "use_tls": "on",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    async with session_factory() as session:
        s = await get_settings(session)
        assert s.smtp_host == "smtp.corp"
        assert s.smtp_port == 465
        assert s.smtp_enabled is True
        assert s.smtp_password_encrypted is not None
        assert s.smtp_password_encrypted != "p@ss"  # şifreli


async def test_settings_smtp_test_no_host(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "admT", Role.admin)
    resp = await client.post("/settings/smtp/test", follow_redirects=False)
    assert resp.status_code == 400  # SMTP sunucusu yok → hata


async def test_settings_smtp_test_sends(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cybersectool.core.app_settings import save_smtp_settings
    from cybersectool.web import routes

    sent: list[str] = []

    async def fake_send_email(row: object, recipient: str, subject: str, body: str) -> None:
        sent.append(recipient)

    monkeypatch.setattr(routes, "send_email", fake_send_email)
    await _login(client, session_factory, "admT2", Role.admin)
    async with session_factory() as session:
        await save_smtp_settings(
            session,
            enabled=True,
            host="smtp.x",
            port=587,
            username="u",
            sender="f@x",
            use_tls=True,
            alert_to="soc@x",
            password="p",
        )
    resp = await client.post("/settings/smtp/test", follow_redirects=False)
    assert resp.status_code == 303
    assert sent == ["soc@x"]


async def test_settings_nvd_save(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """CVE-COVERAGE FE: pencere + API anahtarı kaydedilir (anahtar şifreli)."""
    await _login(client, session_factory, "admN", Role.admin)
    resp = await client.post(
        "/settings/nvd",
        data={"nvd_sync_days": "365", "nvd_api_key": "my-nvd-key"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    async with session_factory() as session:
        s = await get_settings(session)
        assert s.nvd_sync_days == 365
        assert s.nvd_api_key_encrypted is not None
        assert s.nvd_api_key_encrypted != "my-nvd-key"  # şifreli
        assert get_nvd_api_key(s) == "my-nvd-key"


async def test_settings_nvd_backfill_enqueues(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NVD geçmiş yükleme: admin tetikler → arka plan görevi yıl*365 gün ile kuyruğa girer."""
    from cybersectool.web import routes

    captured: dict[str, object] = {}

    def fake_delay(*args: object, **kwargs: object) -> None:
        captured.update(kwargs)

    monkeypatch.setattr(routes.nvd_backfill_task, "delay", fake_delay)

    # is_active()/mark_queued() Redis'e bağlanır; testi hermetik tut: canlı bir Redis
    # erişilebilirse (ör. stack ayakta) önceki state sızıp "zaten aktif" guard'ını
    # tetikleyebilir → görev kuyruğa girmez. Guard'ı "boşta" sabitle, kuyruk işaretini no-op yap.
    async def _not_active() -> bool:
        return False

    async def _noop_queued(**kwargs: object) -> None:
        return None

    monkeypatch.setattr(routes.cve_backfill, "is_active", _not_active)
    monkeypatch.setattr(routes.cve_backfill, "mark_queued", _noop_queued)

    await _login(client, session_factory, "admB", Role.admin)
    resp = await client.post(
        "/settings/nvd/backfill", data={"backfill_years": "2"}, follow_redirects=False
    )
    assert resp.status_code == 303
    assert captured.get("days") == 730  # 2 yıl
    # Üst sınır: 99 yıl → 5 yıla kırpılır.
    captured.clear()
    resp2 = await client.post(
        "/settings/nvd/backfill", data={"backfill_years": "99"}, follow_redirects=False
    )
    assert resp2.status_code == 303
    assert captured.get("days") == 5 * 365


async def test_settings_nvd_backfill_non_admin_forbidden(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Analist geçmiş yüklemeyi tetikleyemez (görev kuyruğa GİRMEZ)."""
    from cybersectool.web import routes

    called = {"n": 0}

    def fake_delay(*args: object, **kwargs: object) -> None:
        called["n"] += 1

    monkeypatch.setattr(routes.nvd_backfill_task, "delay", fake_delay)
    await _login(client, session_factory, "anB", Role.analyst)
    resp = await client.post(
        "/settings/nvd/backfill", data={"backfill_years": "2"}, follow_redirects=False
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/"
    assert called["n"] == 0  # tetiklenmedi


async def test_settings_post_non_admin_forbidden(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "an2", Role.analyst)
    resp = await client.post(
        "/settings/ratelimit",
        data={"max_attempts": "9", "window_sec": "60", "lockout_sec": "60"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/"
    async with session_factory() as session:
        s = await get_settings(session)
        assert s.ratelimit_max_attempts == 5  # analist değiştiremedi
