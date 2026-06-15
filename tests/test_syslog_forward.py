"""Syslog/SIEM forward testleri — formatlar + gönderim + log_action entegrasyonu."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core import audit, syslog_forward
from cybersectool.core.app_settings import save_syslog_settings
from cybersectool.core.models import AppSettings, AuditLog


def _entry(
    action: str = "web_scan", event_id: int = 1004, user_id: int = 3, target: str = "10.0.0.1"
) -> AuditLog:
    return AuditLog(action=action, event_id=event_id, user_id=user_id, target=target)


def _row(**overrides: object) -> AppSettings:
    base: dict[str, object] = {
        "syslog_enabled": True,
        "syslog_host": "siem",
        "syslog_port": 514,
        "syslog_protocol": "udp",
        "syslog_format": "rfc5424",
    }
    base.update(overrides)
    return AppSettings(**base)


def test_format_rfc5424() -> None:
    msg = syslog_forward.format_syslog("rfc5424", _entry())
    assert msg.startswith("<14>1 ")
    assert "action=web_scan" in msg and "event_id=1004" in msg


def test_format_rfc3164() -> None:
    msg = syslog_forward.format_syslog("rfc3164", _entry())
    assert msg.startswith("<14>")
    assert "Kangalis:" in msg and "action=web_scan" in msg


def test_format_cef() -> None:
    msg = syslog_forward.format_syslog("cef", _entry())
    assert msg.startswith("CEF:0|Lineup-NOAH|Kangalis|")
    assert "|1004|web_scan|" in msg


async def test_forward_disabled() -> None:
    assert await syslog_forward.forward_audit(_row(syslog_enabled=False), _entry()) is False


async def test_forward_calls_send(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[tuple[str, int, str, str]] = []

    def fake_send(host: str, port: int, protocol: str, payload: str) -> None:
        sent.append((host, port, protocol, payload))

    monkeypatch.setattr(syslog_forward, "_send_sync", fake_send)
    assert await syslog_forward.forward_audit(_row(syslog_format="cef"), _entry()) is True
    assert len(sent) == 1
    assert sent[0][0] == "siem" and sent[0][3].startswith("CEF:0")


async def test_forward_send_error_returns_false(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(host: str, port: int, protocol: str, payload: str) -> None:
        raise OSError("network down")

    monkeypatch.setattr(syslog_forward, "_send_sync", boom)
    assert await syslog_forward.forward_audit(_row(), _entry()) is False


async def test_log_action_forwards_when_enabled(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    forwarded: list[str] = []

    async def fake_forward(row: AppSettings, entry: AuditLog) -> bool:
        forwarded.append(entry.action)
        return True

    monkeypatch.setattr(audit, "forward_audit", fake_forward)
    async with session_factory() as session:
        await save_syslog_settings(
            session, enabled=True, host="siem", port=514, protocol="udp", fmt="rfc5424"
        )
        await audit.log_action(session, "web_scan", target="x")
        assert forwarded == ["web_scan"]


async def test_log_action_no_forward_when_disabled(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    forwarded: list[str] = []

    async def fake_forward(row: AppSettings, entry: AuditLog) -> bool:
        forwarded.append(entry.action)
        return True

    monkeypatch.setattr(audit, "forward_audit", fake_forward)
    async with session_factory() as session:
        await audit.log_action(session, "web_scan", target="x")
        assert forwarded == []  # syslog varsayılan kapalı
