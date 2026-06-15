"""SMTP e-posta gönderimi — stdlib ``smtplib``, event loop'u bloklamadan.

``app_settings``'teki SMTP ayarlarını kullanır. Parola Fernet ile şifreli saklanır;
gönderim anında çözülür. Senkron ``smtplib`` çağrısı ``asyncio.to_thread`` ile ayrı
bir thread'de çalıştırılır (async uçlardan güvenle çağrılabilir). Yeni bağımlılık yok.
"""

from __future__ import annotations

import asyncio
import smtplib
from email.message import EmailMessage

from cybersectool.core.app_settings import get_smtp_password
from cybersectool.core.models import AppSettings


class MailError(Exception):
    """SMTP gönderimi başarısız (yapılandırma ya da bağlantı/kimlik hatası)."""


def smtp_sender(row: AppSettings) -> str:
    """Gönderen (From) adresi: smtp_from > smtp_username > varsayılan."""
    return row.smtp_from.strip() or row.smtp_username.strip() or "kangalis@localhost"


def _send_sync(
    *,
    host: str,
    port: int,
    use_tls: bool,
    username: str,
    password: str,
    sender: str,
    recipient: str,
    subject: str,
    body: str,
    attachments: list[tuple[str, bytes]] | None = None,
) -> None:
    """Senkron SMTP gönderimi (thread içinde çalışır)."""
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.set_content(body)
    for filename, data in attachments or []:
        msg.add_attachment(data, maintype="application", subtype="pdf", filename=filename)
    # Port 465 = implicit (örtük) SSL: bağlantı ilk andan TLS'tir → SMTP_SSL gerekir.
    # Düz SMTP + STARTTLS denenirse 465'te el sıkışma asılır/başarısız olur (yaygın yapılandırma).
    # 587/25 = explicit STARTTLS (use_tls bayrağına göre).
    implicit_ssl = port == 465
    server = (
        smtplib.SMTP_SSL(host, port, timeout=15)
        if implicit_ssl
        else smtplib.SMTP(host, port, timeout=15)
    )
    with server:
        server.ehlo()
        if use_tls and not implicit_ssl:
            server.starttls()
            server.ehlo()
        if username:
            server.login(username, password)
        server.send_message(msg)


async def send_email(
    row: AppSettings,
    recipient: str,
    subject: str,
    body: str,
    attachments: list[tuple[str, bytes]] | None = None,
) -> None:
    """Tek e-posta gönderir; herhangi bir hata ``MailError`` olarak yükselir.

    ``attachments``: (dosya adı, baytlar) çiftleri — PDF rapor gibi ekler.
    """
    if not row.smtp_host.strip():
        raise MailError("SMTP sunucusu tanımlı değil.")
    if not recipient.strip():
        raise MailError("Alıcı adresi boş.")
    password = get_smtp_password(row)
    try:
        await asyncio.to_thread(
            _send_sync,
            host=row.smtp_host.strip(),
            port=row.smtp_port,
            use_tls=row.smtp_use_tls,
            username=row.smtp_username.strip(),
            password=password,
            sender=smtp_sender(row),
            recipient=recipient.strip(),
            subject=subject,
            body=body,
            attachments=attachments,
        )
    except (OSError, smtplib.SMTPException) as exc:
        raise MailError(f"E-posta gönderilemedi: {exc}") from exc
