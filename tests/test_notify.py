"""Bildirim + kritik bulgu sayım testleri."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.config import settings
from cybersectool.core import notify
from cybersectool.core.assets import upsert_asset
from cybersectool.core.findings import count_critical_for_scan, create_finding
from cybersectool.core.models import ScanType, Severity
from cybersectool.core.scans import create_scan


async def test_send_notification_no_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "notify_webhook_url", "")
    assert await notify.send_notification("merhaba") is False


async def test_count_critical_for_scan(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        asset = await upsert_asset(session, "10.0.0.1")
        scan = await create_scan(session, ScanType.network, "x")
        await create_finding(session, scan.id, "a", severity=Severity.critical, asset_id=asset.id)
        await create_finding(session, scan.id, "b", severity=Severity.high, asset_id=asset.id)
        assert await count_critical_for_scan(session, scan.id) == 1


async def test_notify_if_critical(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    sent: list[str] = []

    async def fake_send(message: str) -> bool:
        sent.append(message)
        return True

    monkeypatch.setattr(notify, "send_notification", fake_send)
    async with session_factory() as session:
        scan = await create_scan(session, ScanType.network, "x")
        # Kritik yokken bildirim gitmez
        assert await notify.notify_if_critical(session, scan.id, "x") == 0
        assert sent == []
        # Kritik bulgu eklenince bildirim gider
        await create_finding(session, scan.id, "boom", severity=Severity.critical)
        assert await notify.notify_if_critical(session, scan.id, "x") == 1
        assert len(sent) == 1 and "KRİTİK" in sent[0]


async def test_notify_if_critical_sends_email_when_smtp_enabled(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    from cybersectool.core.app_settings import save_smtp_settings

    mailed: list[tuple[str, str]] = []

    async def fake_send_notification(message: str) -> bool:
        return True

    async def fake_send_email(row: object, recipient: str, subject: str, body: str) -> None:
        mailed.append((recipient, subject))

    monkeypatch.setattr(notify, "send_notification", fake_send_notification)
    monkeypatch.setattr(notify, "send_email", fake_send_email)
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
        scan = await create_scan(session, ScanType.network, "x")
        await create_finding(session, scan.id, "boom", severity=Severity.critical)
        assert await notify.notify_if_critical(session, scan.id, "x") == 1
        assert mailed == [("soc@x", "Kangalis — Kritik zafiyet uyarısı")]


async def test_notify_if_critical_no_email_when_smtp_disabled(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    mailed: list[str] = []

    async def fake_send_notification(message: str) -> bool:
        return True

    async def fake_send_email(row: object, recipient: str, subject: str, body: str) -> None:
        mailed.append(recipient)

    monkeypatch.setattr(notify, "send_notification", fake_send_notification)
    monkeypatch.setattr(notify, "send_email", fake_send_email)
    async with session_factory() as session:
        scan = await create_scan(session, ScanType.network, "x")
        await create_finding(session, scan.id, "boom", severity=Severity.critical)
        await notify.notify_if_critical(session, scan.id, "x")
        assert mailed == []  # SMTP kapalı → e-posta gönderilmez


# --- Dalga 1: AI yönetici özetini tamamlanma e-postasına taşı (salt-okunur önbellek) ---


async def _enable_smtp(session: AsyncSession) -> None:
    from cybersectool.core.app_settings import save_smtp_settings

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


async def test_notify_assigned_user_includes_ai_summary(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Önbellekte AI özeti varsa tamamlanma e-postasının gövdesine eklenir."""
    from cybersectool.core.models import AIExplanation
    from cybersectool.core.users import create_user

    sent: list[tuple[str, str]] = []

    async def fake_send_email(
        row: object, recipient: str, subject: str, body: str, attachments: object = None
    ) -> None:
        sent.append((recipient, body))

    monkeypatch.setattr(notify, "send_email", fake_send_email)
    async with session_factory() as session:
        await _enable_smtp(session)
        owner = await create_user(session, "owner", "pass1234", email="owner@x")
        scan = await create_scan(
            session,
            ScanType.network,
            "10.0.0.5",
            assigned_user_id=owner.id,
            notify_on_complete=True,
        )
        session.add(
            AIExplanation(
                cache_key=f"summary:scan:{scan.id}",
                content="Bu ağda 3 kritik açık var. Önceliğiniz Apache olmalı.",
                model="qwen3:8b",
            )
        )
        await session.commit()
        assert await notify.notify_assigned_user(session, scan.id) is True
        assert len(sent) == 1
        recipient, body = sent[0]
        assert recipient == "owner@x"
        assert "AI Yönetici Özeti" in body
        assert "doğrulayın" in body  # sorumluluk reddi
        assert "Önceliğiniz Apache olmalı." in body


async def test_notify_assigned_user_without_ai_summary_unchanged(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    """AI özeti üretilmemişse (cache miss) gövde özetsiz, bozulmadan gider (graceful)."""
    from cybersectool.core.users import create_user

    sent: list[str] = []

    async def fake_send_email(
        row: object, recipient: str, subject: str, body: str, attachments: object = None
    ) -> None:
        sent.append(body)

    monkeypatch.setattr(notify, "send_email", fake_send_email)
    async with session_factory() as session:
        await _enable_smtp(session)
        owner = await create_user(session, "owner2", "pass1234", email="owner2@x")
        scan = await create_scan(
            session,
            ScanType.network,
            "10.0.0.6",
            assigned_user_id=owner.id,
            notify_on_complete=True,
        )
        assert await notify.notify_assigned_user(session, scan.id) is True
        assert len(sent) == 1
        assert "AI Yönetici Özeti" not in sent[0]
