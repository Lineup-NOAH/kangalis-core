"""SMTP mailer testleri — gerçek sunucuya bağlanmaz; _send_sync monkeypatch'lenir."""

from __future__ import annotations

import smtplib

import pytest

from cybersectool.core import mailer
from cybersectool.core.mailer import MailError, send_email, smtp_sender
from cybersectool.core.models import AppSettings


def _row(**overrides: object) -> AppSettings:
    base: dict[str, object] = {
        "smtp_enabled": True,
        "smtp_host": "smtp.x",
        "smtp_port": 587,
        "smtp_username": "u",
        "smtp_from": "from@x",
        "smtp_use_tls": True,
        "alert_email_to": "soc@x",
        "smtp_password_encrypted": None,
    }
    base.update(overrides)
    return AppSettings(**base)


def test_smtp_sender_fallback() -> None:
    assert smtp_sender(_row(smtp_from="a@x")) == "a@x"
    assert smtp_sender(_row(smtp_from="", smtp_username="u@x")) == "u@x"
    assert smtp_sender(_row(smtp_from="", smtp_username="")) == "kangalis@localhost"


async def test_send_email_requires_host() -> None:
    with pytest.raises(MailError):
        await send_email(_row(smtp_host=""), "to@x", "s", "b")


async def test_send_email_requires_recipient() -> None:
    with pytest.raises(MailError):
        await send_email(_row(), "   ", "s", "b")


async def test_send_email_success(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, object]] = []

    def fake_send(**kw: object) -> None:
        calls.append(kw)

    monkeypatch.setattr(mailer, "_send_sync", fake_send)
    await send_email(_row(), "to@x", "Konu", "Gövde")
    assert len(calls) == 1
    assert calls[0]["recipient"] == "to@x"
    assert calls[0]["host"] == "smtp.x"
    assert calls[0]["sender"] == "from@x"
    assert calls[0]["subject"] == "Konu"


async def test_send_email_wraps_smtp_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_send(**kw: object) -> None:
        raise smtplib.SMTPException("boom")

    monkeypatch.setattr(mailer, "_send_sync", fake_send)
    with pytest.raises(MailError):
        await send_email(_row(), "to@x", "s", "b")


async def test_send_email_passes_attachments(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ekler (PDF rapor) _send_sync'e değişmeden iletilir."""
    calls: list[dict[str, object]] = []

    def fake_send(**kw: object) -> None:
        calls.append(kw)

    monkeypatch.setattr(mailer, "_send_sync", fake_send)
    pdf = [("rapor.pdf", b"PDF")]
    await send_email(_row(), "to@x", "Konu", "Gövde", attachments=pdf)
    assert calls[0]["attachments"] == pdf


def test_send_sync_adds_attachment() -> None:
    """_send_sync ekleri EmailMessage'a iliştirir (SMTP'ye gitmeden mesajı doğrula)."""
    import smtplib as _smtp
    from email.message import EmailMessage

    captured: list[EmailMessage] = []

    class _FakeSMTP:
        def __init__(self, *a: object, **k: object) -> None: ...
        def __enter__(self) -> _FakeSMTP:
            return self

        def __exit__(self, *a: object) -> None: ...
        def ehlo(self) -> None: ...
        def starttls(self) -> None: ...
        def login(self, *a: object) -> None: ...
        def send_message(self, msg: EmailMessage) -> None:
            captured.append(msg)

    orig = _smtp.SMTP
    _smtp.SMTP = _FakeSMTP  # type: ignore[assignment,misc]
    try:
        mailer._send_sync(
            host="smtp.x",
            port=587,
            use_tls=False,
            username="",
            password="",
            sender="f@x",
            recipient="to@x",
            subject="s",
            body="b",
            attachments=[("rapor.pdf", b"PDF")],
        )
    finally:
        _smtp.SMTP = orig  # type: ignore[misc]
    assert captured, "mesaj gönderilmedi"
    names = [p.get_filename() for p in captured[0].iter_attachments()]
    assert "rapor.pdf" in names


def test_send_sync_port_465_uses_smtp_ssl() -> None:
    """ORTA fix: port 465 (örtük SSL) → SMTP_SSL kullanılır + STARTTLS denenmez (asılmaz)."""
    import smtplib as _smtp
    from email.message import EmailMessage

    used = {"ssl": False, "plain": False, "starttls": False}

    class _FakeSSL:
        def __init__(self, *a: object, **k: object) -> None:
            used["ssl"] = True

        def __enter__(self) -> _FakeSSL:
            return self

        def __exit__(self, *a: object) -> None: ...
        def ehlo(self) -> None: ...
        def starttls(self) -> None:
            used["starttls"] = True

        def login(self, *a: object) -> None: ...
        def send_message(self, msg: EmailMessage) -> None: ...

    class _FakePlain(_FakeSSL):
        def __init__(self, *a: object, **k: object) -> None:
            used["plain"] = True

    orig_ssl, orig = _smtp.SMTP_SSL, _smtp.SMTP
    _smtp.SMTP_SSL = _FakeSSL  # type: ignore[assignment,misc]
    _smtp.SMTP = _FakePlain  # type: ignore[assignment,misc]
    try:
        mailer._send_sync(
            host="smtp.x",
            port=465,
            use_tls=True,
            username="u",
            password="p",
            sender="f@x",
            recipient="to@x",
            subject="s",
            body="b",
        )
    finally:
        _smtp.SMTP_SSL, _smtp.SMTP = orig_ssl, orig  # type: ignore[misc]
    assert used["ssl"] is True and used["plain"] is False
    assert used["starttls"] is False  # implicit SSL'de STARTTLS çağrılmaz
