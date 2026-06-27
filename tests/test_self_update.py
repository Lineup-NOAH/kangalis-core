"""Uygulama-içi otomatik güncelleme — saf mantık + /update/apply rota kapıları.

Docker/host'a HİÇ dokunmaz: saf yardımcılar doğrudan; rota testlerinde ``trigger_self_update`` /
``self_update_status`` monkeypatch'lenir. Sürüm probe'ları (nmap/redis) deterministik yapılır.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import cybersectool.core.versions as ver
from cybersectool.core import self_update as su
from cybersectool.core.app_settings import get_settings
from cybersectool.core.models import Role
from cybersectool.core.users import create_user


async def _login(
    client: AsyncClient,
    factory: async_sessionmaker[AsyncSession],
    username: str,
    role: Role,
) -> None:
    async with factory() as s:
        await create_user(s, username, "pass1234", role=role)
    await client.post(
        "/login", data={"username": username, "password": "pass1234"}, follow_redirects=False
    )


def _fast_versions(monkeypatch: pytest.MonkeyPatch) -> None:
    """nmap/redis probe'larını hızlı + dış-bağımlılıksız yapar (render testleri için)."""
    monkeypatch.setattr(ver, "nmap_version", lambda: "7.94")

    async def _no_redis() -> None:
        return None

    monkeypatch.setattr(ver, "redis_version", _no_redis)


# ---- saf mantık (docker yok) ----


def test_project_info_reads_labels() -> None:
    c = {
        "Config": {
            "Labels": {
                "com.docker.compose.project": "kangalis-core",
                "com.docker.compose.project.working_dir": "/srv/kangalis",
            }
        }
    }
    assert su._project_info(c) == ("kangalis-core", "/srv/kangalis")


def test_project_info_missing_returns_none() -> None:
    assert su._project_info({}) is None
    # working_dir eksik → None (yarım bilgiyle iş başlatma)
    assert su._project_info({"Config": {"Labels": {"com.docker.compose.project": "x"}}}) is None


def test_project_regex_blocks_injection() -> None:
    assert su._PROJECT_RE.match("kangalis-core")
    assert su._PROJECT_RE.match("k_1.2-3")
    assert not su._PROJECT_RE.match("a; rm -rf /")
    assert not su._PROJECT_RE.match("$(touch x)")
    assert not su._PROJECT_RE.match("")


def test_updater_cmd_forces_project_and_pull() -> None:
    cmd = su._updater_cmd("kangalis-core")
    assert cmd[:2] == ["sh", "-c"]
    assert "docker compose -p kangalis-core build" in cmd[2]
    assert "docker compose -p kangalis-core up -d" in cmd[2]
    assert "git pull --ff-only" in cmd[2]  # klon değilse başarısız → yarım güncelleme yok


def test_demux_framed_and_plain() -> None:
    payload = b"build ok\n"
    frame = b"\x01\x00\x00\x00" + len(payload).to_bytes(4, "big") + payload
    assert "build ok" in su._demux_logs(frame)  # çerçeveli (TTY'siz) akış
    assert "plain log" in su._demux_logs(b"plain log")  # çerçevesiz (TTY) ham metin


# ---- rota kapıları ----


async def test_apply_requires_admin(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "su_an", Role.analyst)
    resp = await client.post("/update/apply", follow_redirects=False)
    assert resp.status_code in (302, 303)
    assert resp.headers.get("location") == "/"


async def test_apply_disabled_does_not_trigger(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Opt-in KAPALI (varsayılan) → trigger ÇAĞRILMAZ (güvenlik sınırı)."""
    import cybersectool.web.routes as routes

    _fast_versions(monkeypatch)
    called = {"n": 0}

    async def _fake() -> su.UpdateLaunch:
        called["n"] += 1
        return su.UpdateLaunch(True, "x")

    monkeypatch.setattr(routes, "trigger_self_update", _fake)
    await _login(client, session_factory, "su_ad1", Role.admin)
    resp = await client.post("/update/apply")
    assert resp.status_code == 200
    assert called["n"] == 0  # opt-in kapalı → tetiklenmedi


async def test_apply_enabled_triggers(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Opt-in AÇIK → trigger çağrılır; 'başladı' paneli render olur."""
    import cybersectool.web.routes as routes

    _fast_versions(monkeypatch)
    async with session_factory() as s:
        row = await get_settings(s)
        row.update_apply_enabled = True
        await s.commit()

    async def _fake() -> su.UpdateLaunch:
        return su.UpdateLaunch(True, "Guncelleme baslatildi.")

    monkeypatch.setattr(routes, "trigger_self_update", _fake)
    await _login(client, session_factory, "su_ad2", Role.admin)
    resp = await client.post("/update/apply")
    assert resp.status_code == 200
    assert "apply-panel" in resp.text  # "güncelleme başladı" izleme paneli


async def test_apply_status_requires_admin(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "su_an2", Role.analyst)
    resp = await client.get("/update/apply/status")
    assert resp.status_code == 403


async def test_apply_status_admin_json(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import cybersectool.web.routes as routes

    async def _fake_status() -> su.UpdateStatus:
        return su.UpdateStatus(state="running", exit_code=None, log_tail="building...")

    monkeypatch.setattr(routes, "self_update_status", _fake_status)
    await _login(client, session_factory, "su_ad3", Role.admin)
    resp = await client.get("/update/apply/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["state"] == "running"
    assert "building" in data["log_tail"]
