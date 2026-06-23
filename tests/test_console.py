"""Admin güvenli komut konsolu (core/console.py + /console rotaları).

Kapsam: allowlist (bilinmeyen komut çalışmaz), help, scan list, scope-dışı scan start
(broker'a girmez — kapsam dışı atlanır), kullanıcı yönetimi + kilitlenme korumaları,
sync (send_task monkeypatch), license/plugin/logs, ve rota admin-gating'i.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core import console
from cybersectool.core.console import run_console
from cybersectool.core.models import Role
from cybersectool.core.users import create_user, get_user_by_username


async def _admin(session_factory: async_sessionmaker[AsyncSession], username: str = "con_adm"):
    async with session_factory() as s:
        await create_user(s, username, "pass1234", role=Role.admin)
    async with session_factory() as s:
        user = await get_user_by_username(s, username)
        assert user is not None
        return user


# --- run_console birim testleri ---


async def test_unknown_command_does_not_run(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Kayıtlı olmayan komut ÇALIŞMAZ (allowlist) — ok=False + 'bilinmeyen'."""
    user = await _admin(session_factory)
    async with session_factory() as s:
        res = await run_console(s, user, "rm -rf /", "tr")
    assert res.ok is False
    assert "ilinmeyen" in res.output  # "Bilinmeyen komut"


async def test_empty_command(session_factory: async_sessionmaker[AsyncSession]) -> None:
    user = await _admin(session_factory, "con_e")
    async with session_factory() as s:
        res = await run_console(s, user, "   ", "tr")
    assert res.ok is False


async def test_help_lists_commands(session_factory: async_sessionmaker[AsyncSession]) -> None:
    user = await _admin(session_factory, "con_h")
    async with session_factory() as s:
        res = await run_console(s, user, "help", "tr")
    assert res.ok is True
    # Birkaç temel komut help çıktısında görünmeli.
    for token in ("scan", "sync", "user", "system", "worker", "logs"):
        assert token in res.output


async def test_scan_list_runs(session_factory: async_sessionmaker[AsyncSession]) -> None:
    user = await _admin(session_factory, "con_sl")
    async with session_factory() as s:
        res = await run_console(s, user, "scan list", "tr")
    assert res.ok is True  # tarama yoksa bile "Tarama yok." (ok)


async def test_scan_start_out_of_scope_skips(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Aktif ScopePolicy yokken hedef kapsam dışı → tarama AÇILMAZ (broker'a girmez)."""
    user = await _admin(session_factory, "con_ss")
    async with session_factory() as s:
        res = await run_console(s, user, "scan start 10.0.0.5", "tr")
    assert res.ok is True
    assert "kapsam dışı" in res.output


async def test_user_role_change(session_factory: async_sessionmaker[AsyncSession]) -> None:
    user = await _admin(session_factory, "con_ur")
    async with session_factory() as s:
        await create_user(s, "victim", "pass1234", role=Role.viewer)
    async with session_factory() as s:
        res = await run_console(s, user, "user role victim analyst", "tr")
    assert res.ok is True
    async with session_factory() as s:
        victim = await get_user_by_username(s, "victim")
        assert victim is not None and victim.role == Role.analyst


async def test_user_role_invalid(session_factory: async_sessionmaker[AsyncSession]) -> None:
    user = await _admin(session_factory, "con_uri")
    async with session_factory() as s:
        await create_user(s, "victim2", "pass1234", role=Role.viewer)
    async with session_factory() as s:
        res = await run_console(s, user, "user role victim2 superadmin", "tr")
    assert res.ok is False
    assert "rol" in res.output.lower()


async def test_user_self_demote_blocked(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Admin kendini düşüremez (kilitlenme koruması)."""
    user = await _admin(session_factory, "con_self")
    async with session_factory() as s:
        res = await run_console(s, user, "user role con_self viewer", "tr")
    assert res.ok is False
    async with session_factory() as s:
        me = await get_user_by_username(s, "con_self")
        assert me is not None and me.role == Role.admin  # değişmedi


async def test_user_self_disable_blocked(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    user = await _admin(session_factory, "con_sd")
    async with session_factory() as s:
        res = await run_console(s, user, "user disable con_sd", "tr")
    assert res.ok is False
    async with session_factory() as s:
        me = await get_user_by_username(s, "con_sd")
        assert me is not None and me.is_active is True


async def test_sync_triggers_send_task(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """sync nvd → celery send_task('cpe_sync') (broker yerine kayıt mock)."""
    user = await _admin(session_factory, "con_sy")
    sent: list[str] = []
    monkeypatch.setattr(console.celery_app, "send_task", lambda name, *a, **k: sent.append(name))
    async with session_factory() as s:
        res = await run_console(s, user, "sync nvd", "tr")
    assert res.ok is True
    assert sent == ["cpe_sync"]


async def test_sync_invalid(session_factory: async_sessionmaker[AsyncSession]) -> None:
    user = await _admin(session_factory, "con_syi")
    async with session_factory() as s:
        res = await run_console(s, user, "sync bogus", "tr")
    assert res.ok is False


async def test_license_status_runs(session_factory: async_sessionmaker[AsyncSession]) -> None:
    user = await _admin(session_factory, "con_lic")
    async with session_factory() as s:
        res = await run_console(s, user, "license status", "tr")
    assert res.ok is True
    assert "Lisans" in res.output


async def test_plugin_status_runs(session_factory: async_sessionmaker[AsyncSession]) -> None:
    user = await _admin(session_factory, "con_pl")
    async with session_factory() as s:
        res = await run_console(s, user, "plugin status", "tr")
    assert res.ok is True


async def test_logs_runs(session_factory: async_sessionmaker[AsyncSession]) -> None:
    user = await _admin(session_factory, "con_lg")
    async with session_factory() as s:
        res = await run_console(s, user, "logs 5", "tr")
    assert res.ok is True


# --- Rota admin-gating ---


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


async def test_console_page_admin(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "con_pg", Role.admin)
    resp = await client.get("/console")
    assert resp.status_code == 200
    assert 'hx-post="/console/exec"' in resp.text


async def test_console_page_non_admin_redirected(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "con_an", Role.analyst)
    resp = await client.get("/console", follow_redirects=False)
    assert resp.status_code in (302, 303)
    assert resp.headers["location"] == "/"


async def test_console_exec_admin(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "con_ex", Role.admin)
    resp = await client.post("/console/exec", data={"cmd": "help"}, follow_redirects=False)
    assert resp.status_code == 200
    assert "scan" in resp.text  # help çıktısı fragment'ta


async def test_console_exec_non_admin_redirected(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await _login(client, session_factory, "con_exa", Role.analyst)
    resp = await client.post("/console/exec", data={"cmd": "user list"}, follow_redirects=False)
    assert resp.status_code in (302, 303)
