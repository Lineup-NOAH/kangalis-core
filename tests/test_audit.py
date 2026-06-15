"""Denetim günlüğü sayfası + servis testleri."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.audit import (
    UNKNOWN_EVENT_ID,
    event_id_for,
    export_audit_logs,
    list_audit_logs,
    log_action,
    query_audit_logs,
    range_since,
)
from cybersectool.core.models import Role
from cybersectool.core.users import create_user


async def test_list_audit_logs_order(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        await log_action(session, "first")
        await log_action(session, "second")
        logs = await list_audit_logs(session)
        assert logs[0].action == "second"  # en yeni önce


def test_event_id_for() -> None:
    assert event_id_for("scan_start") == 1001
    assert event_id_for("ldap_user_import") == 7002
    assert event_id_for("totally_unknown_action") == UNKNOWN_EVENT_ID


def test_range_since() -> None:
    now = datetime(2026, 6, 5, tzinfo=UTC)
    assert range_since("day", now) == now - timedelta(days=1)
    assert range_since("week", now) == now - timedelta(days=7)
    assert range_since("month", now) == now - timedelta(days=30)
    assert range_since("all", now) is None
    assert range_since("nonsense", now) is None


async def test_log_action_sets_event_id(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        entry = await log_action(session, "token_create", target="t")
        assert entry.event_id == 5001


async def test_audit_since_filter_and_export(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        await log_action(session, "scan_start")
        await log_action(session, "zone_create")
        # since gelecekte → hiç kayıt
        future = datetime.now(UTC) + timedelta(days=1)
        assert await list_audit_logs(session, since=future) == []
        # export tüm aralık (eski→yeni)
        rows = await export_audit_logs(session)
        assert len(rows) == 2
        assert rows[0].action == "scan_start"  # eski önce


async def test_query_audit_logs_keyword(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """X-7: anahtar kelime action/target içinde (büyük-küçük harf duyarsız) eşleşir."""
    async with session_factory() as session:
        await log_action(session, "scan_start", target="10.0.0.0/24")
        await log_action(session, "user_create", target="alice")
        # 'scan' yalnızca scan_start'ı yakalar.
        rows = await query_audit_logs(session, keyword="SCAN")
        assert len(rows) == 1
        assert rows[0].action == "scan_start"
        # target üzerinden eşleşme.
        rows = await query_audit_logs(session, keyword="alice")
        assert len(rows) == 1
        assert rows[0].action == "user_create"


async def test_query_audit_logs_event_id(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """X-7: event_id ile tam eşleşme filtresi."""
    async with session_factory() as session:
        await log_action(session, "scan_start")  # 1001
        await log_action(session, "token_create")  # 5001
        rows = await query_audit_logs(session, event_id=5001)
        assert len(rows) == 1
        assert rows[0].action == "token_create"


async def test_query_audit_logs_date_range(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """X-7: gelecekteki date_from → kayıt yok; geçmiş date_from → hepsi."""
    async with session_factory() as session:
        await log_action(session, "scan_start")
        future = datetime.now(UTC) + timedelta(days=1)
        assert await query_audit_logs(session, date_from=future) == []
        past = datetime.now(UTC) - timedelta(days=1)
        assert len(await query_audit_logs(session, date_from=past)) == 1


async def test_query_audit_logs_matched_user_ids(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """X-7: anahtar kelime kullanıcı adıyla da eşleşir (matched_user_ids ile)."""
    async with session_factory() as session:
        u = await create_user(session, "bob", "pass1234", role=Role.admin)
        await log_action(session, "scan_start", user_id=u.id, target="10.0.0.0/24")
        # 'bob' ne action ne target'ta var; sadece matched_user_ids ile bulunur.
        rows = await query_audit_logs(session, keyword="bob", matched_user_ids=[u.id])
        assert len(rows) == 1
        assert rows[0].user_id == u.id
        # matched_user_ids verilmezse eşleşme olmaz.
        assert await query_audit_logs(session, keyword="bob") == []


async def test_audit_page_admin(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    async with session_factory() as session:
        await create_user(session, "adm", "pass1234", role=Role.admin)
        await log_action(session, "scan_start", target="10.0.0.0/24")
    await client.post("/auth/login", json={"username": "adm", "password": "pass1234"})
    resp = await client.get("/audit")
    assert resp.status_code == 200
    assert "Denetim Günlüğü" in resp.text
    assert "scan_start" in resp.text


async def test_audit_page_viewer_redirected(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    async with session_factory() as session:
        await create_user(session, "vi", "pass1234", role=Role.viewer)
    await client.post("/auth/login", json={"username": "vi", "password": "pass1234"})
    resp = await client.get("/audit", follow_redirects=False)
    assert resp.status_code == 303


async def test_audit_export_csv_and_json(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    async with session_factory() as session:
        await create_user(session, "adm2", "pass1234", role=Role.admin)
        await log_action(session, "scan_start", target="10.0.0.0/24")
    await client.post("/auth/login", json={"username": "adm2", "password": "pass1234"})

    csv_resp = await client.get("/audit/export?range=all&fmt=csv")
    assert csv_resp.status_code == 200
    assert "text/csv" in csv_resp.headers["content-type"]
    assert "attachment" in csv_resp.headers.get("content-disposition", "")
    assert "event_id" in csv_resp.text  # başlık satırı
    assert "scan_start" in csv_resp.text

    json_resp = await client.get("/audit/export?range=week&fmt=json")
    assert json_resp.status_code == 200
    assert "application/json" in json_resp.headers["content-type"]
    data = json_resp.json()
    assert any(row["action"] == "scan_start" and row["event_id"] == 1001 for row in data)


async def test_audit_export_viewer_forbidden(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    async with session_factory() as session:
        await create_user(session, "vi2", "pass1234", role=Role.viewer)
    await client.post("/auth/login", json={"username": "vi2", "password": "pass1234"})
    resp = await client.get("/audit/export?fmt=csv", follow_redirects=False)
    assert resp.status_code == 303
