"""Sistem/Servisler paneli — saf yardımcılar + admin rota render (Docker soketi mock'lu)."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.models import Role
from cybersectool.core.system_health import (
    ContainerStat,
    DiskInfo,
    SystemHealth,
    _cpu_pct,
    _docker_disk,
    _filter_own_project,
    _host_disk,
    _mem_used,
)
from cybersectool.core.users import create_user

# --- saf yardımcılar (Docker gerekmez) ---


def test_cpu_pct() -> None:
    stats = {
        "cpu_stats": {
            "cpu_usage": {"total_usage": 200},
            "system_cpu_usage": 2000,
            "online_cpus": 2,
        },
        "precpu_stats": {"cpu_usage": {"total_usage": 100}, "system_cpu_usage": 1000},
    }
    # cpu_delta=100, sys_delta=1000, 2 cpu → 100/1000*2*100 = 20.0
    assert _cpu_pct(stats) == 20.0
    assert _cpu_pct({}) is None  # eksik alan → None
    # delta yoksa (ilk okuma) 0.0
    zero = {
        "cpu_stats": {"cpu_usage": {"total_usage": 100}, "system_cpu_usage": 1000},
        "precpu_stats": {"cpu_usage": {"total_usage": 100}, "system_cpu_usage": 1000},
    }
    assert _cpu_pct(zero) == 0.0


def test_mem_used_drops_cache() -> None:
    assert _mem_used({"usage": 1000, "stats": {"inactive_file": 200}}) == 800
    assert _mem_used({"usage": 500, "stats": {"cache": 100}}) == 400
    assert _mem_used({"usage": 500}) == 500
    assert _mem_used({}) is None


def test_docker_disk_sums_layers_and_volumes() -> None:
    df = {
        "LayersSize": 1000,
        "Volumes": [{"UsageData": {"Size": 500}}, {"UsageData": {"Size": 250}}],
    }
    assert _docker_disk(df) == 1750
    assert _docker_disk({}) == 0


def test_host_disk_real_call() -> None:
    info = _host_disk()
    assert info is None or (info.total > 0 and 0.0 <= info.pct <= 100.0)


def test_filter_own_project_keeps_only_app() -> None:
    raw = [
        {
            "Id": "abc123def456",
            "Labels": {"com.docker.compose.project": "cybersectool"},
            "Names": ["/cybersectool-app-1"],
        },
        {
            "Id": "db00",
            "Labels": {"com.docker.compose.project": "cybersectool"},
            "Names": ["/cybersectool-db-1"],
        },
        {
            "Id": "lab01",
            "Labels": {"com.docker.compose.project": "fixtures"},
            "Names": ["/kg-vuln-web"],
        },
        {"Id": "rnd1", "Labels": {}, "Names": ["/random"]},
    ]
    # Kendi konteyneri abc123… (cybersectool projesi) → yalnız cybersectool-* kalır.
    kept = _filter_own_project(raw, "abc123")
    names = {c["Names"][0] for c in kept}
    assert names == {"/cybersectool-app-1", "/cybersectool-db-1"}
    # Proje tespit edilemezse (eşleşmeyen own_id) → güvenli düşüş, hepsi kalır.
    assert len(_filter_own_project(raw, "yokyok")) == 4
    # Env override ile.
    assert len(_filter_own_project(raw, "", override="fixtures")) == 1


# --- web rota (Docker soketi mock'lanır) ---


async def _login_admin(
    client: AsyncClient, factory: async_sessionmaker[AsyncSession], name: str, role: Role
) -> None:
    async with factory() as session:
        await create_user(session, name, "pass1234", role=role)
    await client.post("/auth/login", json={"username": name, "password": "pass1234"})


async def test_system_panel_admin_renders(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await _login_admin(client, session_factory, "sysadm", Role.admin)

    async def fake_health() -> SystemHealth:
        return SystemHealth(
            available=True,
            containers=[
                ContainerStat(
                    name="cybersectool-app-1",
                    image="cybersectool-app",
                    state="running",
                    status="Up 2 hours",
                    cpu_pct=12.3,
                    mem_used=100,
                    mem_limit=1000,
                    mem_pct=10.0,
                )
            ],
            disk=DiskInfo(total=100, used=40, free=60, pct=40.0),
        )

    monkeypatch.setattr("cybersectool.web.routes.system_health", fake_health)
    page = await client.get("/system")
    assert page.status_code == 200
    assert "Sistem Servisleri" in page.text
    panel = await client.get("/system/panel")
    assert panel.status_code == 200
    assert "cybersectool-app" in panel.text
    assert "Up 2 hours" in panel.text


async def test_system_unavailable_shows_message(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await _login_admin(client, session_factory, "sysadm2", Role.admin)

    async def fake_health() -> SystemHealth:
        return SystemHealth(available=False, error="Docker soketi bulunamadı — test.")

    monkeypatch.setattr("cybersectool.web.routes.system_health", fake_health)
    panel = await client.get("/system/panel")
    assert panel.status_code == 200
    assert "Docker soketi bulunamadı" in panel.text


async def test_system_non_admin_blocked(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login_admin(client, session_factory, "viewer1", Role.viewer)
    page = await client.get("/system", follow_redirects=False)
    assert page.status_code == 303  # admin değil → ana sayfaya
    panel = await client.get("/system/panel")
    assert panel.status_code == 403
