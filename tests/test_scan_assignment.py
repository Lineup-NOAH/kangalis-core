"""Tarama atama + tamamlanma e-postası (opsiyonel PDF rapor) testleri."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core import notify
from cybersectool.core.app_settings import save_smtp_settings
from cybersectool.core.models import Role, ScanMode, ScanStatus, ScanType, Severity
from cybersectool.core.scan_batches import create_batch, get_batch
from cybersectool.core.scans import create_scan, set_scan_status
from cybersectool.core.users import create_user


async def _enable_smtp(session: AsyncSession) -> None:
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


async def test_create_scan_persists_assignment_fields(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        u = await create_user(session, "ass1", "p", role=Role.viewer, email="a@x")
        scan = await create_scan(
            session,
            ScanType.network,
            "10.0.0.1",
            assigned_user_id=u.id,
            notify_on_complete=True,
            attach_report=True,
        )
        assert scan.assigned_user_id == u.id
        assert scan.notify_on_complete is True
        assert scan.attach_report is True


async def test_create_batch_persists_assignment_fields(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        u = await create_user(session, "ass2", "p", role=Role.viewer, email="b@x")
        batch = await create_batch(
            session,
            "İş",
            ScanMode.safe,
            None,
            None,
            assigned_user_id=u.id,
            notify_on_complete=True,
            attach_report=False,
        )
        assert batch.assigned_user_id == u.id
        assert batch.notify_on_complete is True
        assert batch.attach_report is False
        assert batch.notified_at is None


def _capture_mail(
    monkeypatch: pytest.MonkeyPatch,
) -> list[dict[str, object]]:
    """notify.send_email'i yakalayan sahte ile değiştirir; çağrı kayıtlarını döndürür."""
    calls: list[dict[str, object]] = []

    async def fake_send_email(
        row: object,
        recipient: str,
        subject: str,
        body: str,
        attachments: object = None,
    ) -> None:
        calls.append({"recipient": recipient, "subject": subject, "attachments": attachments})

    monkeypatch.setattr(notify, "send_email", fake_send_email)
    return calls


async def test_standalone_scan_sends_when_assigned(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _capture_mail(monkeypatch)
    async with session_factory() as session:
        await _enable_smtp(session)
        u = await create_user(session, "asgn", "p", role=Role.viewer, email="x@x")
        scan = await create_scan(
            session, ScanType.network, "t", assigned_user_id=u.id, notify_on_complete=True
        )
        assert await notify.notify_assigned_user(session, scan.id) is True
        assert len(calls) == 1
        assert calls[0]["recipient"] == "x@x"
        assert calls[0]["attachments"] is None


async def test_no_send_when_notify_off(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _capture_mail(monkeypatch)
    async with session_factory() as session:
        await _enable_smtp(session)
        u = await create_user(session, "asn2", "p", role=Role.viewer, email="x@x")
        scan = await create_scan(
            session, ScanType.network, "t", assigned_user_id=u.id, notify_on_complete=False
        )
        assert await notify.notify_assigned_user(session, scan.id) is False
        assert calls == []


async def test_no_send_when_assignee_has_no_email(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _capture_mail(monkeypatch)
    async with session_factory() as session:
        await _enable_smtp(session)
        u = await create_user(session, "asn3", "p", role=Role.viewer, email=None)
        scan = await create_scan(
            session, ScanType.network, "t", assigned_user_id=u.id, notify_on_complete=True
        )
        assert await notify.notify_assigned_user(session, scan.id) is False
        assert calls == []


async def test_no_send_when_smtp_disabled(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _capture_mail(monkeypatch)
    async with session_factory() as session:
        # SMTP etkinleştirilmedi (varsayılan kapalı)
        u = await create_user(session, "asn4", "p", role=Role.viewer, email="x@x")
        scan = await create_scan(
            session, ScanType.network, "t", assigned_user_id=u.id, notify_on_complete=True
        )
        assert await notify.notify_assigned_user(session, scan.id) is False
        assert calls == []


async def test_batch_sends_only_when_last_member_terminal(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _capture_mail(monkeypatch)
    async with session_factory() as session:
        await _enable_smtp(session)
        u = await create_user(session, "basn", "p", role=Role.viewer, email="x@x")
        batch = await create_batch(
            session,
            "Batch",
            ScanMode.safe,
            None,
            None,
            assigned_user_id=u.id,
            notify_on_complete=True,
        )
        s1 = await create_scan(session, ScanType.network, "a", batch_id=batch.id)
        s2 = await create_scan(session, ScanType.network, "b", batch_id=batch.id)
        # İlk taramayı tamamla → diğeri terminal değil → gönderilmez
        await set_scan_status(session, s1.id, ScanStatus.completed)
        assert await notify.notify_assigned_user(session, s1.id) is False
        assert calls == []
        # İkinci (son) taramayı tamamlamadan önce hook çağrılır (mevcut scan terminal sayılır)
        assert await notify.notify_assigned_user(session, s2.id) is True
        assert len(calls) == 1
        batch_after = await get_batch(session, batch.id)
        assert batch_after is not None and batch_after.notified_at is not None
        # İkinci çağrı → tekrar gönderilmez (notified_at guard)
        assert await notify.notify_assigned_user(session, s2.id) is False
        assert len(calls) == 1


async def test_attach_report_passes_pdf_attachment(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _capture_mail(monkeypatch)
    monkeypatch.setattr(notify, "render_summary_pdf", lambda **kw: b"PDF")
    async with session_factory() as session:
        await _enable_smtp(session)
        u = await create_user(session, "pdfa", "p", role=Role.viewer, email="x@x")
        scan = await create_scan(
            session,
            ScanType.network,
            "t",
            assigned_user_id=u.id,
            notify_on_complete=True,
            attach_report=True,
        )
        # Bir bulgu ekle (özet sayımının çalıştığını da görür)
        from cybersectool.core.findings import create_finding

        await create_finding(session, scan.id, "boom", severity=Severity.high)
        assert await notify.notify_assigned_user(session, scan.id) is True
        assert calls[0]["attachments"] == [("kangalis-rapor.pdf", b"PDF")]
